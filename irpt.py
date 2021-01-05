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

BASIC_CMD  = 'python3 framework/%s.py '
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

def test_cmd(args):
    cmd = BASIC_CMD % ('irpt_test', args['driver'], args['interface'], args['vm'])
    os.system(cmd)

def repro_cmd(args):
    cmd  = BASIC_CMD % ('irpt_repro', args['driver'], args['interface'], args['vm'])
    cmd += '-payload %s ' % args['payload']
    if args['revert']:
        cmd += "-revert "

    os.system(cmd)
    os.system('kill -9 `pgrep qemu` 2>/dev/null')

def fuzz_cmd(args):
    cmd = BASIC_CMD % ('irpt_fuzz', args['driver'], args['interface'], args['vm'])
    if args['revert']:
        cmd += "-revert "

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

def add_args_reprodunction(parser):
    parser.add_argument('-payload', metavar='<file>', required=False, action=FullPath,
                        type=parse_is_file, help='path to interface of target driver.')

modes = ['fuzz', 'test', 'repro']
modes_help = '''fuzz:\tkernel fuzzing mode
test:\tioctl code coverage testing mode
repro:\treproduce target payload.
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
    elif mode == 'test':
        test_cmd(args)
    elif mode == 'repro':
        if args['payload']:
            repro_cmd(args)
        else:
            print("repro mode requires payload.")
    else:
        print("Invalid mode")


if __name__ == '__main__':
    main()