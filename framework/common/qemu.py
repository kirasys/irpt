# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
# Copyright 2020-2021 Namjun Jo (kirasys@theori.io)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Launch Qemu VMs and execute test inputs produced by framework.
"""
import sys
import ctypes
import mmap
import os
import resource
import select
import socket
import struct
import subprocess
import time
import traceback
from socket import error as socket_error

import common.color
import common.qemu_protocol as qemu_protocol

from wdm.irp import IRP
from common.debug import log_qemu
from common.execution_result import ExecutionResult
from common.util import read_binary_file, atomic_write, print_fail, print_warning, strdump, p32
from debug.log import log

def to_string_32(value):
    return [(value >> 24) & 0xff,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff]


class qemu:
    CMDS = qemu_protocol.CMDS

    def __init__(self, qid, config, debug_mode=False, notifiers=True):

        self.hprintf_print_mode = True
        self.internal_buffer_overflow_counter = 0

        # True => handshake *not yet done*
        self.handshake_stage_1 = True
        self.handshake_stage_2 = True

        self.debug_mode = debug_mode
        self.debug_counter = 0

        self.agent_size = config.config_values['AGENT_MAX_SIZE']
        self.bitmap_size = config.config_values['BITMAP_SHM_SIZE']
        self.coverage_map_size = config.config_values['COVERAGE_MAP_SHM_SIZE']
        self.payload_size = config.config_values['PAYLOAD_SHM_SIZE']
        self.config = config
        self.qemu_id = str(qid)

        self.process = None
        self.control = None
        self.persistent_runs = 0

        project_name = self.config.argument_values['work_dir'].split("/")[-1]
        self.payload_filename = "/dev/shm/kafl_%s_qemu_payload_%s" % (project_name, self.qemu_id)
        self.tracedump_filename = "/dev/shm/kafl_%s_pt_trace_dump_%s" % (project_name, self.qemu_id)
        self.binary_filename = self.config.argument_values['work_dir'] + "/program"
        self.bitmap_filename = "/dev/shm/kafl_%s_bitmap_%s" % (project_name, self.qemu_id)
        self.coverage_map_filename = "/dev/shm/kafl_%s_coverage_map_%s" % (project_name, self.qemu_id)

        self.control_filename = self.config.argument_values['work_dir'] + "/interface_" + self.qemu_id
        self.qemu_trace_log = self.config.argument_values['work_dir'] + "/qemu_trace_%s.log" % self.qemu_id
        self.qemu_serial_log = self.config.argument_values['work_dir'] + "/qemu_serial_%s.log" % self.qemu_id

        self.exiting = False
        self.timeout_threshold = self.config.config_values["TIMEOUT_THRESHOLD"]

        self.cmd = self.config.config_values['QEMU_LOCATION']

        # TODO: list append should work better than string concatenation, especially for str.replace() and later popen()
        self.cmd += " -serial file:" + self.qemu_serial_log + \
                    " -enable-kvm -nographic " \
                    " -m " + str(config.argument_values['mem']) + \
                    " -net none " + \
                    " -chardev socket,server,nowait,path=" + self.control_filename + \
                    ",id=kafl_interface " + \
                    "-device kafl,chardev=kafl_interface" + \
                    ",bitmap_size=" + str(self.bitmap_size) + \
                    ",coverage_map_size=" + str(self.coverage_map_size) + \
                    ",shm0=" + self.binary_filename + \
                    ",shm1=" + self.payload_filename + \
                    ",bitmap=" + self.bitmap_filename + \
                    ",coverage_map=" + self.coverage_map_filename

        if False:  # do not emit tracefiles on every execution
            self.cmd += ",dump_pt_trace"

        if self.debug_mode:
            self.cmd += ",debug_mode"

        if not notifiers:
            self.cmd += ",crash_notifier=False"

        # if not self.config.argument_values.has_key('R') or not self.config.argument_values['R']:
        self.cmd += ",reload_mode=False"

        # qemu snapshots only work in VM mode (disk+ram image)
        if self.config.argument_values['kernel'] or self.config.argument_values['bios']:
            self.cmd += ",disable_snapshot=True"

        for i in range(1):
            key = "ip" + str(i)
            if key in self.config.argument_values and self.config.argument_values[key]:
                range_a = hex(self.config.argument_values[key][0]).replace("L", "")
                range_b = hex(self.config.argument_values[key][1]).replace("L", "")
                self.cmd += ",ip" + str(i) + "_a=" + range_a + ",ip" + str(i) + "_b=" + range_b
                #self.cmd += ",filter" + str(i) + "=/dev/shm/kafl_filter" + str(i)

        if self.debug_mode:
            self.cmd += " -d kafl -D " + self.qemu_trace_log

        if self.config.argument_values['extra']:
            self.cmd += " " + self.config.argument_values['extra']

        # Lauch either as VM snapshot, direct kernel/initrd boot, or -bios boot
        if self.config.argument_values['vm_dir']:
            assert(self.config.argument_values['vm_ram'])
            self.cmd += " -hdb " + self.config.argument_values['vm_ram']
            self.cmd += " -hda " + self.config.argument_values['vm_dir'] + "/overlay_" + self.qemu_id + ".qcow2"
            self.cmd += " -loadvm " + self.config.argument_values["S"]
        elif self.config.argument_values['kernel']:
            self.cmd += " -kernel " + self.config.argument_values['kernel']
            if self.config.argument_values['initrd']:
                self.cmd += " -initrd " + self.config.argument_values['initrd'] + " -append BOOTPARAM "
        elif self.config.argument_values['bios']:
            self.cmd += " -bios " + self.config.argument_values['bios']
        else:
            assert(False), "Must supply either -bios or -kernel or -vm_overlay/-vm_ram option"

        self.cmd += " -machine q35 "

        self.crashed = False
        self.timeout = False
        self.kasan = False

        self.virgin_bitmap = bytes(self.bitmap_size)

        # split cmd into list of arguments for Popen(), replace BOOTPARAM as single element
        self.cmd = [_f for _f in self.cmd.split(" ") if _f]
        c = 0
        for i in self.cmd:
            if i == "BOOTPARAM":
                self.cmd[c] = "\"nokaslr oops=panic nopti mitigations=off\""
                break
            c += 1

        # select a reload mode.
        self.reload_driver = self._revert_driver if config.argument_values['revert'] else self._reload_driver

    def __debug_hprintf(self):
        try:
            if self.debug_counter < 512:
                data = ""
                for line in open("/tmp/kAFL_printf.txt." + str(self.debug_counter)):
                    data += line
                self.debug_counter += 1
                if data.endswith('\n'):
                    data = data[:-1]
                if self.hprintf_print_mode:
                    print("[HPRINTF]\t" + '\033[0;33m' + data + '\033[0m')
                else:
                    print('\033[0;33m' + data + '\033[0m')
        except Exception as e:
            print("__debug_hprintf: " + str(e))

    def __debug_send(self, cmd):
        #self.last_bitmap_wrapper.invalidate() # works on a copy, probably obsolete..
        if self.debug_mode:
                info = ""
                if self.handshake_stage_1 and cmd == qemu_protocol.RELEASE:
                    info = " (Agent Init)"
                    self.handshake_stage_1 = False
                elif self.handshake_stage_2 and cmd == qemu_protocol.RELEASE:
                    info = " (Agent Run)"
                    self.handshake_stage_2 = False
                try:
                    log_qemu("[SEND] " + '\033[94m' + self.CMDS[cmd] + info + '\033[0m', self.qemu_id)
                except:
                    log_qemu("[SEND] " + "unknown cmd '" + cmd + "'", self.qemu_id)
        try:
            self.control.send(cmd)
        except (BrokenPipeError, OSError):
            if not self.exiting:
                log_qemu("Fatal error in __debug_send()", self.qemu_id)
                self.shutdown()
                raise

    def __dump_recv_res(self, res):
        if res == qemu_protocol.ACQUIRE:
            self.debug_counter = 0
        # try:
        info = ""
        if self.handshake_stage_1 and res == qemu_protocol.RELEASE:
            info = " (Agent Init)"
        elif self.handshake_stage_2 and res == qemu_protocol.ACQUIRE:
            info = " (Agent Ready)"
        elif res == qemu_protocol.INFO:
            log_qemu("[RECV] " + '\033[1m' + '\033[92m' + self.CMDS[res] + info + '\033[0m', self.qemu_id)
            log_qemu("------------------------------------------------------", self.qemu_id)
            try:
                for line in open("/tmp/kAFL_info.txt"):
                    log_qemu(line, self.qemu_id)
                os.remove("/tmp/kAFL_info.txt")
            except:
                pass
            log_qemu("------------------------------------------------------", self.qemu_id)
            os._exit(0)
        elif res == qemu_protocol.ABORT:
            #print(common.color.FAIL + self.CMDS[res] + common.color.ENDC)
            log_qemu("[RECV] " + common.color.FAIL + self.CMDS[res] + common.color.ENDC, self.qemu_id)
            os._exit(0)
        if res == qemu_protocol.CRASH or res == qemu_protocol.KASAN:
            log_qemu("[RECV] " + '\033[1m' + '\033[91m' + self.CMDS[res] + info + '\033[0m', self.qemu_id)
        else:
            try:
                log_qemu("[RECV] " + '\033[1m' + '\033[92m' + self.CMDS[res] + info + '\033[0m', self.qemu_id)
            except Exception as e:
                log_qemu("[RECV] " + "unknown cmd '" + res + "'" + str(e), self.qemu_id)
                raise e

    def recv(self):
        return self.control.recv(1)     

    def __debug_recv(self):
        while True:
            try:
                res = self.control.recv(1)
            except ConnectionResetError:
                if self.exiting:
                    sys.exit(0)
                raise

            if (len(res) == 0):
                # Another case of socket error, apparently on Qemu reset/crash
                # Default: assume Qemu exit is fatal bug in harness/setup
                log_qemu("Fatal error in __debug_recv()", self.qemu_id)
                sig = self.shutdown()
                if sig == 0: # regular shutdown? still report as KASAN
                    return qemu_protocol.KASAN
                else:
                    raise BrokenPipeError("Qemu exited with signal: %s" % str(sig))

            if res == qemu_protocol.PRINTF:
                self.__debug_hprintf()
                self.hprintf_print_mode = False
            else:
                self.hprintf_print_mode = True

                if self.debug_mode:
                    try:
                        self.__dump_recv_res(res)
                    except:
                        pass

                return res

    def __debug_recv_expect(self, cmd):
        res = ''
        while True:
            res = self.__debug_recv()
            if res in cmd:
                break
            # TODO: the I/O handling here really sucks.
            # Below we are returning OK to set_init_state() in order to silence handshake error message during kafl_info.py.
            # We need to factor out the debug stuff and properly support required vs optional/intermediate control messages...
            elif res == qemu_protocol.INFO:
                break
            elif res is None:
                # Timeout is detected separately in debug_recv(), so we should never get here..
                assert False
            else:
                # Reaching this part typically means there is a bug in the agent or target setup which
                # messes up the expected interaction. Throw an error and kill Qemu. Slave may retry.
                log_qemu("Error in debug_recv(): Got " + str(res) + ", Expected: " + str(cmd) + ")", self.qemu_id)
                print_warning("Slave %s: Error in debug_recv(): Got %s, Expected: %s" % (self.qemu_id, str(res), str(cmd)))
                self.shutdown()
                raise ConnectionResetError("Killed Qemu due to protocol error.")
        if res == qemu_protocol.PT_TRASHED:
            log_qemu("PT_TRASHED", self.qemu_id)
            return False
        return True

    # Asynchronous exit by slave instance. Note this may be called multiple times
    # while we were in the middle of shutdown(), start(), send_payload(), ..
    def async_exit(self):
        if self.exiting:
            sys.exit(0)

        self.exiting = True
        self.shutdown()

        for tmp_file in [
                self.payload_filename,
                self.tracedump_filename,
                self.control_filename,
                self.binary_filename,
                self.bitmap_filename,
                self.coverage_map_filename]:
            try:
                os.remove(tmp_file)
            except:
                pass


    def shutdown(self):
        log_qemu("Shutting down Qemu after %d execs.." % self.persistent_runs, self.qemu_id)
        
        if not self.process:
            # start() has never been called, all files/shm are closed.
            return 0

        # If Qemu exists, try to graciously read its I/O and SIGTERM it.
        # If still alive, attempt SIGKILL or loop-wait on kill -9.
        output = "<no output received>\n"
        try:
            self.process.terminate()
            output = strdump(self.process.communicate(timeout=1)[0], verbatim=True)
        except:
            pass

        if self.process.returncode is None:
            try:
                self.process.kill()
            except:
                pass

        log_qemu("Qemu exit code: %s" % str(self.process.returncode), self.qemu_id)
        header = "\n=================<Qemu %s Console Output>==================\n" % self.qemu_id
        footer = "====================</Console Output>======================\n"
        log_qemu(header + output + footer, self.qemu_id)

        if os.path.isfile(self.qemu_serial_log):
            header = "\n=================<Qemu %s Serial Output>==================\n" % self.qemu_id
            footer = "====================</Serial Output>======================\n"
            serial_out = strdump(read_binary_file(self.qemu_serial_log), verbatim=True)
            log_qemu(header + serial_out + footer, self.qemu_id)


        try:
            # TODO: exec_res keeps from_buffer() reference to kafl_shm
            self.kafl_shm.close()
        except BufferError as e:
            pass

        try:
            self.fs_shm.close()
        except:
            pass

        try:
            os.close(self.kafl_shm_f)
        except:
            pass
        
        try:
            os.close(self.c_shm_f)
        except:
            pass

        try:
            os.close(self.fs_shm_f)
        except:
            pass

        return self.process.returncode

    def __set_agent_and_driver(self):
        driver_bin = read_binary_file(self.config.argument_values['driver'])
        bin  = p32(len(driver_bin)) + driver_bin
        agent_bin = read_binary_file(self.config.argument_values['agent'])
        bin += p32(len(agent_bin)) + agent_bin
        assert (len(bin) <= self.agent_size)
        atomic_write(self.binary_filename, bin)

    def start(self):

        if self.exiting:
            return False

        self.persistent_runs = 0
        self.handshake_stage_1 = True
        self.handshake_stage_2 = True

        if self.qemu_id == "0" or self.qemu_id == "1337": ## 1337 is debug instance!
            log_qemu("Launching virtual machine...CMD:\n" + ' '.join(self.cmd), self.qemu_id)
        else:
            log_qemu("Launching virtual machine...", self.qemu_id)


        # Launch Qemu. stderr to stdout, stdout is logged on VM exit
        # os.setpgrp() prevents signals from being propagated to Qemu, instead allowing an
        # organized shutdown via async_exit()
        self.process = subprocess.Popen(self.cmd,
                preexec_fn=os.setpgrp,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)

        try:
            self.__qemu_connect()
            self.__qemu_handshake()
        except (OSError, BrokenPipeError) as e:
            if not self.exiting:
                print_fail("Failed to launch Qemu, please see logs. Error: " + str(e))
                log_qemu("Fatal error: Failed to launch Qemu: " + str(e), self.qemu_id)
                self.shutdown()
            return False

        return True

    def __qemu_handshake(self):
        if self.config.argument_values['agent'] and self.config.argument_values['driver'] :
            self.__set_agent_and_driver()

        self.__debug_send(qemu_protocol.RELEASE) # unlock
        while True:
            res = self.__debug_recv()
            if res == qemu_protocol.LOCK:
                break
            self.__debug_send(qemu_protocol.RELEASE)

        self.__debug_recv_expect(qemu_protocol.RELEASE)
        self.__debug_recv()

        log_qemu("Handshake done [INIT]", self.qemu_id)

    def __qemu_connect(self):
        # Note: setblocking() disables the timeout! settimeout() will automatically set blocking!
        self.control = socket.socket(socket.AF_UNIX)
        self.control.settimeout(None)
        self.control.setblocking(1)

        # TODO: Don't try forever, set some timeout..
        while True:
            try:
                self.control.connect(self.control_filename)
                break
            except socket_error:
                if self.process.returncode is not None:
                    raise

        self.kafl_shm_f     = os.open(self.bitmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.c_shm_f        = os.open(self.coverage_map_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.fs_shm_f       = os.open(self.payload_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)

        open(self.tracedump_filename, "wb").close()

        with open(self.binary_filename, 'bw') as f:
            os.ftruncate(f.fileno(), self.agent_size)

        os.ftruncate(self.kafl_shm_f, self.bitmap_size)
        os.ftruncate(self.c_shm_f, self.coverage_map_size)
        os.ftruncate(self.fs_shm_f, self.payload_size)

        self.kafl_shm = mmap.mmap(self.kafl_shm_f, 0)
        self.c_bitmap = (ctypes.c_uint8 * self.bitmap_size).from_buffer(self.kafl_shm)
        self.c_shm = mmap.mmap(self.c_shm_f, 0)
        self.c_coverage_map = (ctypes.c_uint8 * self.coverage_map_size).from_buffer(self.c_shm)
        self.fs_shm = mmap.mmap(self.fs_shm_f, 0)

        return True

    # Fully stop/start Qemu instance to store logs + possibly recover
    def restart(self):

        self.shutdown()
        # TODO: Need to wait here or else the next instance dies in set_payload()
        # Perhaps Qemu should do proper munmap()/close() on exit?
        os.system('kill -9 `pgrep qemu` 2>/dev/null')
        return self.start()

    # Reset Qemu after crash/timeout
    def reload(self):
        return self.restart()

    # Reload is not part of released Redqueen backend, it seems we can simply disable it here..
    def soft_reload(self):
        return

        log_qemu("soft_reload()", self.qemu_id)
        self.crashed = False
        self.timeout = False
        self.kasan = False

        self.__debug_send(qemu_protocol.RELOAD)
        self.__debug_recv_expect(qemu_protocol.RELOAD)
        success = self.__debug_recv_expect(qemu_protocol.ACQUIRE + qemu_protocol.PT_TRASHED)

        if not success:
            log_qemu("soft reload failed (ipt ovp quirk)", self.qemu_id)
            self.soft_reload()

    # TODO: can directly return result for handling by caller?
    # TODO: document protocol and meaning/effect of each message
    def check_recv(self, timeout_detection=True):
        if timeout_detection:
            ready = select.select([self.control], [], [], self.timeout_threshold)
            if not ready[0]:
                return 2
        result = self.__debug_recv()

        if result == qemu_protocol.CRASH:
            return 1
        elif result == qemu_protocol.KASAN:
            return 3
        elif result == qemu_protocol.TIMEOUT:
            return 7
        elif result == qemu_protocol.ACQUIRE:
            return 0
        elif result == qemu_protocol.PT_TRASHED:
            self.internal_buffer_overflow_counter += 1
            return 4
        elif result == qemu_protocol.PT_TRASHED_CRASH:
            self.internal_buffer_overflow_counter += 1
            return 5
        elif result == qemu_protocol.PT_TRASHED_KASAN:
            self.internal_buffer_overflow_counter += 1
            return 6
        else:
            # TODO: detect+log errors without affecting fuzz campaigns
            #raise ValueError("Unhandled Qemu message %s" % repr(result))
            return 0

    # Wait forever on Qemu to execute the payload - useful for interactive debug
    def debug_payload(self):
        self.__debug_send(qemu_protocol.RELEASE)

        while True:
            ready = select.select([self.control], [], [], 0.5)
            if ready[0]:
                break

        result = self.__debug_recv()
        return result

    def send_payload(self, timeout_detection=True, max_iterations=10,):
        if (self.debug_mode):
            log_qemu("Send payload..", self.qemu_id)

        if self.exiting:
            sys.exit(0)

        self.persistent_runs += 1
        start_time = time.time()
        self.__debug_send(qemu_protocol.RELEASE)
        
        self.crashed = False
        self.timeout = False
        self.kasan = False

        repeat = False
        value = self.check_recv(timeout_detection=timeout_detection)
        
        if value == 0:
            pass # all good
        elif value == 1:
            log_qemu("Crash detected!", self.qemu_id)
            self.crashed = True
        elif value == 2:
            log_qemu("Timeout detected!", self.qemu_id)
            self.timeout = True
        elif value == 3:
            log_qemu("Kasan detected!", self.qemu_id)
            self.kasan = True
        elif value == 4:
            repeat = True
        elif value == 5:
            repeat = True
            self.soft_reload()
        elif value == 6:
            repeat = True
            self.soft_reload()
        elif value == 7:
            log_qemu("Timeout detected!", self.qemu_id)
            self.timeout = True
        else:
            # TODO: detect+log errors without affecting fuzz campaigns
            #raise ValueError("Unhandled return code %s" % str(value))
            pass

        ## repeat logic - enable starting with RQ release..
        if repeat:
            log_qemu("Repeating iteration...", self.qemu_id)
            if max_iterations != 0:
                self.send_payload(timeout_detection=timeout_detection, max_iterations=0)
                res = self.send_payload(timeout_detection=timeout_detection,
                                        max_iterations=max_iterations - 1)
                res.performance = time.time() - start_time
                return res

        return ExecutionResult(self.c_bitmap, self.c_coverage_map,
                                self.bitmap_size, self.exit_reason(), time.time() - start_time)

    def exit_reason(self):
        if self.crashed:
            return "crash"
        elif self.timeout:
            return "timeout"
        elif self.kasan:
            return "kasan"
        else:
            return "regular"

    def enable_coverage_map(self, retry=0):
        try:
            self.__debug_send(qemu_protocol.COVERAGE_ON)
        except BrokenPipeError:
            time.sleep(0.2)
            os.system('kill -9 `pgrep qemu` 2>/dev/null')
            self.reload()
            self.__debug_send(qemu_protocol.COVERAGE_ON)
    
    def disable_coverage_map(self, retry=0):
        self.__debug_send(qemu_protocol.COVERAGE_OFF)

    def set_payload(self, irp):
        if self.exiting:
            sys.exit(0)

        # actual payload is limited to payload_size - sizeof(uint32) - sizeof(uint8)
        try:
            self.fs_shm.seek(0)
            self.fs_shm.write(p32(irp.Command))
            self.fs_shm.write(p32(irp.IoControlCode))
            self.fs_shm.write(p32(irp.InBufferLength))
            self.fs_shm.write(p32(irp.OutBufferLength))
            self.fs_shm.write(bytes(irp.InBuffer))
            self.fs_shm.flush()
        except ValueError:
            if self.exiting:
                sys.exit(0)
            # Qemu crashed. Could be due to prior payload but more likely harness/config is broken..
            #print_fail("Failed to set new payload - Qemu crash?");
            log_qemu("Failed to set new payload - Qemu crash?", self.qemu_id)
            raise

    def send_irp(self, irp, retry=0):
        try:
            #log(f"iocode: {hex(irp.IoControlCode)}, payload: {bytes(irp.InBuffer[:0x10])}.., len: {hex(irp.InBufferLength)}", label='IRP')
            self.set_payload(irp)
            return self.send_payload()
        except (ValueError, BrokenPipeError):
            if retry > 2:
                # TODO if it reliably kills qemu, perhaps log to master for harvesting..
                print_fail("Process aborting due to repeated SHM/socket error. Check logs.")
                log_qemu("Aborting due to repeated SHM/socket error", self.qemu_id)
                raise
            print_warning("SHM/socket error on Process (retry %d)" % retry)
            log_qemu("SHM/socket error, trying to restart qemu...", self.qemu_id)
            if not self.restart():
                raise
        return self.send_irp(irp, retry=retry+1)
    
    def _revert_driver(self):
        try:
            self.send_irp(IRP(0, 0, 0, command=qemu_protocol.DRIVER_REVERT))
        except ConnectionResetError:
            sys.exit()
    
    def _reload_driver(self):
        self.send_irp(IRP(0, 0, 0, command=qemu_protocol.DRIVER_RELOAD))
    
    def enable_anti_ioctl_filter(self):
        self.send_irp(IRP(0, 0, 0, command=qemu_protocol.ANTI_IOCTL_FILTER))
    