import os
import sys
import time
import argparse
import multiprocessing

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

BASIC_CMD  = 'python3 kAFL-Fuzzer/%s.py '
BASIC_CMD += '-vm_ram snapshot_win/wram.qcow2 '
BASIC_CMD += '-vm_dir snapshot_win/ '
BASIC_CMD += '-agent targets/bin/agent.exe '
BASIC_CMD += '-driver %s '
BASIC_CMD += '-mem 4096 '
BASIC_CMD += '-seed_dir in/ '
BASIC_CMD += '-work_dir out/ '
BASIC_CMD += '-d '
BASIC_CMD += '-v '
BASIC_CMD += '--purge '
BASIC_CMD += '-interface %s '
BASIC_CMD += '-S %s '

def ioctl_coverage_cmd(args):
    cmd = BASIC_CMD % ('ioctl_coverage', args['driver'], args['interface'], args['vm'])
    os.system(cmd)

def reproduction_cmd(args):
    cmd  = BASIC_CMD % ('reproduction', args['driver'], args['interface'], args['vm'])
    cmd += '-payload %s ' % args['payload']
    if args['revert']:
        cmd += "-revert "

    os.system(cmd)
    os.system('kill -9 `pgrep qemu` 2>/dev/null')

def fuzz_cmd(args):
    cmd = BASIC_CMD % ('kafl_fuzz', args['driver'], args['interface'], args['vm'])
    if args['revert']:
        cmd += "-revert "

    if args['tui']:
        cmd += "-tui "
        monitor_cmd = "python3 kAFL-Fuzzer/kafl_mon.py out " + os.path.basename(args['driver'])

        while True:
            row, col = os.popen('stty size', 'r').read().split()
            if int(row) < 27 or int(col) < 82:
                print("Your terminal is too small to show monitor!")
                time.sleep(1)
            else:
                break
        
        procs = [multiprocessing.Process(target=os.system, args=(cmd,)),
                 multiprocessing.Process(target=os.system, args=(monitor_cmd,))]
        for proc in procs:
            time.sleep(1)
            proc.start()
        for proc in procs:
            proc.join()
    else:
        os.system(cmd)



def add_args_general(parser):
    parser.add_argument('-driver', metavar='<file>', required=True, action=FullPath,
                        type=parse_is_file, help='path to target driver.')
    parser.add_argument('-device', required=True, help='Device name of target driver.')
    parser.add_argument('-interface', metavar='<file>', required=True, action=FullPath,
                        type=parse_is_file, help='path to payload to reproduce.', default=None)
    parser.add_argument('-vm', required=False, help='Name of the snapshot (default: irpt)', default="irpt")
    parser.add_argument('-revert', required=False, help="enable driver revert mode.",
                        action='store_true', default=False)
    parser.add_argument('-tui', required=False, help="enable TUI based monitor",
                        action='store_true', default=False)

def add_args_reprodunction(parser):
    parser.add_argument('-payload', metavar='<file>', required=False, action=FullPath,
                        type=parse_is_file, help='path to interface of target driver.')

modes = ['fuzz', 'ioctl_coverage', 'reproduction']
modes_help = '''fuzz:\tkernel fuzzing mode
ioctl_coverage:\tioctl code coverage testing mode
reproduction:\treproduce target payload.
'''

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, add_help=False)
    parser.add_argument('-mode', metavar='mode', choices=modes, help=modes_help, required=True)

    general = parser.add_argument_group('General options')
    add_args_general(general)
    repro = parser.add_argument_group('Reproduction options')
    add_args_reprodunction(repro)

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit()

    args = vars(parser.parse_args())
    os.chdir(BASEDIR)

    # Compile an agent
    with open('targets/include/driver.h.template', 'rt') as fin:
        with open('targets/include/driver.h', 'wt') as fout:
            for line in fin:
                fout.write(line.replace('@@DEVICE_NAME@@', args['device']))
    os.system('x86_64-w64-mingw32-g++ targets/src/agent.cpp -I targets/include -o targets/bin/agent.exe -mwindows -lpsapi -lntdll -Wall')

    # Mode execution
    mode = args['mode']
    if mode == 'fuzz':
        fuzz_cmd(args)
    elif mode == 'ioctl_coverage':
        ioctl_coverage_cmd(args)
    elif mode == 'reproduction':
        if args['payload']:
            reproduction_cmd(args)
        else:
            print("reproduction mode requires payload.")
    else:
        print("Invalid mode")


if __name__ == '__main__':
    main()