#  irec.py
#
#  Copyright 2020 Namjun Jo <kirasys@theori.io>
#
#  Redistribution and use in source and binary forms, with or without modification,
#  are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#    * Neither the name of {{ project }} nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
# 
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
#  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import argparse

BASEDIR = os.path.dirname(os.path.abspath(__file__))

class FullPath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))

def parse_is_file(dirname):
    if not os.path.isfile(dirname):
        msg = "{0} is not a file".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname

modes = ['boot', 'snapshot']
modes_help = '''boot:\tboot target os.
snapshot:\ttake a snapshot to fuzz.
'''

def boot_cmd(args):
    cmd  = './qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 '
    cmd += '-machine q35 -enable-kvm -m 4096 -smp 4 '
    cmd += '-hda %s -vga vmware ' % args['qcow2']
    cmd += '-chardev socket,server,nowait,path=./out/interface_0,id=kafl_interface '
    cmd += '-device kafl,chardev=kafl_interface,bitmap_size=65536,shm0=./out/program,shm1=/dev/shm/kafl_out_qemu_payload_0,bitmap=/dev/shm/kafl_out_bitmap_0,reload_mode=False '
    if args['snapshot']:
        cmd += '-snapshot '
    os.system(cmd)
    pass

def snapshot_cmd(args):
    if not os.path.isdir('snapshot_win'):
        os.mkdir('snapshot_win')
    if not os.path.isdir('out'):
        os.mkdir('out')

    os.system('./qemu-5.0.0/qemu-img create -b %s -f qcow2 ./snapshot_win/overlay_0.qcow2' % args['qcow2'])
    os.system('./qemu-5.0.0/qemu-img create -f qcow2 ./snapshot_win/wram.qcow2 4096')

    cmd  = './qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 '
    cmd += '-hdb ./snapshot_win/wram.qcow2 '
    cmd += '-hda ./snapshot_win/overlay_0.qcow2 '
    cmd += '-machine q35 -enable-kvm -m 4096 '
    cmd += '-serial mon:stdio '
    cmd += '-net none '
    os.system(cmd)

def add_args_general(parser):
    parser.add_argument('-qcow2', metavar='<file>', required=True, action=FullPath,
                        type=parse_is_file, help='path to target driver.')
    parser.add_argument('-snapshot', required=False, help='turn on snapshot mode.', action='store_true', default=False)

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, add_help=False)
    parser.add_argument('-mode', metavar='mode', choices=modes, help=modes_help, required=True)

    general = parser.add_argument_group('General options')
    add_args_general(general)

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit()

    args = vars(parser.parse_args())
    os.chdir(BASEDIR)

    # Mode execution
    mode = args['mode']
    if mode == 'boot':
        boot_cmd(args)
    elif mode == 'snapshot':
        snapshot_cmd(args)
    else:
        print("Invalid mode")


if __name__ == '__main__':
    main()