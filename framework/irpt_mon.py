import os
import sys
import signal
import time
import glob
import random
import psutil
import curses
import msgpack
import inotify.adapters
from threading import Thread, Lock

from common.util import read_binary_file

WORKDIR = ''
SVCNAME = ''

# screen width
WIDTH = 80

# color pair code
WHITE = 1
RED = 2
GREEN = 3
YELLOW = 4
BLUE = 5
MAGENTA = 6
CYAN = 7

BOLD = curses.A_BOLD
DIM = curses.A_DIM

def sigint_handler(sig, frame):
    curses.endwin()
    sys.exit(0)

# helper function for color pairs
def color(code):
    return curses.color_pair(code)

# helper function for formatting number
def pnum(num):
    assert num >= 0
    if num <= 9999:
        return "%d" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fk" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fm" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fg" % num
    num /= 1000.0
    if num <= 999:
        return "%.1ft" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fp" % num
    assert False

def pfloat(flt):
    assert flt >= 0
    if flt <= 999:
        return "%.2f" % flt
    return pnum(flt)

def pbyte(num):
    assert num >= 0
    if num <= 999:
        return "%d" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fk" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fm" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fg" % num
    num /= 1024.0
    if num <= 999:
        return "%.1ft" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fp" % num
    assert False

# helper function for formatting timestamps
def ptime(secs):
    if not secs:
        return "none yet"

    secs = int(secs)
    seconds = secs % 60
    secs //= 60
    mins = secs % 60
    secs //= 60
    hours = secs % 24
    days = secs  // 24
    return "%d days, %d hrs, %d min, %d sec" % (days, hours, mins, seconds)


class MonitorInterface:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.y = 0

    def print_title(self):
        self.y += 1

        title1 = 'Interface Recovery-PT '
        title2 = f'({SVCNAME})'
        title3 = '2020 KITRI Best of the Best'
        center_len = len(title1) + len(title2)
        pad_len1 = (WIDTH - center_len) // 2
        pad_len2 = (WIDTH - len(title3)) // 2
        pad1 = ' ' * pad_len1
        pad2 = ' ' * pad_len2

        x = 0
        self.stdscr.addstr(self.y, x, pad1, BOLD)
        x += pad_len1
        self.stdscr.addstr(self.y, x, title1, color(YELLOW) + BOLD)
        x += len(title1)
        self.stdscr.addstr(self.y, x, title2, color(CYAN) + BOLD)
        x += len(title2)
        self.stdscr.addstr(self.y, x, pad1, BOLD)
        self.y += 1

        x = 0
        self.stdscr.addstr(self.y, x, pad2, BOLD)
        x += pad_len2
        self.stdscr.addstr(self.y, x, title3, color(GREEN) + BOLD)
        self.y += 2

    def print_guest_and_overall(self):
        self.stdscr.addstr(self.y, 0, '┌─', DIM)
        self.stdscr.addstr(self.y, 2, ' process timing ', color(CYAN))
        self.stdscr.addstr(self.y, 18, '─'*38 + '┬─', DIM)
        self.stdscr.addstr(self.y, 58, ' overall results ', color(CYAN))
        self.stdscr.addstr(self.y, 75, '─'*5 + '┐', DIM)
        self.y += 1

    def print_cycle_and_map(self):
        self.stdscr.addstr(self.y, 0, '├─', DIM)
        self.stdscr.addstr(self.y, 2, ' cycle progress ', color(CYAN))
        self.stdscr.addstr(self.y, 18, '─'*21 + '┬─', DIM)
        self.stdscr.addstr(self.y, 41, ' map coverage ', color(CYAN))
        self.stdscr.addstr(self.y, 55,  '─┴'+ '─'*23 + '┤', DIM)
        self.y += 1

    def print_stage_and_findings(self):
        self.stdscr.addstr(self.y, 0, '├─', DIM)
        self.stdscr.addstr(self.y, 2, ' stage progress ', color(CYAN))
        self.stdscr.addstr(self.y, 18, '─'*21 + '┼─', DIM)
        self.stdscr.addstr(self.y, 41, ' findings in depth ', color(CYAN))
        self.stdscr.addstr(self.y, 60,  '─'*20 + '┤', DIM)
        self.y += 1

    def print_strategy_and_geometry(self):
        self.stdscr.addstr(self.y, 0, '├─', DIM)
        self.stdscr.addstr(self.y, 2, ' fuzzing strategy yields', color(CYAN))
        self.stdscr.addstr(self.y, 27, '─'*12 + '┴─' + '─'*15 + '┬─', DIM)
        self.stdscr.addstr(self.y, 58,  ' path geometry ', color(CYAN))
        self.stdscr.addstr(self.y, 73, '─'*7 + '┤', DIM)
        self.y += 1

    def print_last_two_line(self, cpu_used):
        self.stdscr.addstr(self.y-1, 56, '├' + '─'*23 + '┘', DIM)
        self.stdscr.addstr(self.y, 0, '└' + '─'*55 + '┘', DIM)
        if cpu_used < 30:
            self.stdscr.addstr(self.y, 71, '[cpu: ', DIM)
            self.stdscr.addstr(self.y, 77, f"{pnum(cpu_used)}%", color(GREEN) + BOLD)
            self.stdscr.addstr(self.y, 77 + len(pnum(cpu_used)) + 1, ']\n', DIM)
        elif cpu_used < 100:
            self.stdscr.addstr(self.y, 71, '[cpu: ', DIM)
            self.stdscr.addstr(self.y, 77, f"{pnum(cpu_used)}%", color(RED) + BOLD)
            self.stdscr.addstr(self.y, 77 + len(pnum(cpu_used)) + 1, ']\n', DIM)
        self.y += 1

    def print_payload_info(self):
        self.stdscr.addstr(self.y, 0, '├─', DIM)
        self.stdscr.addstr(self.y, 2, ' payload info ', color(CYAN))
        self.stdscr.addstr(self.y, 16, '─'*20 + '┴─', DIM)
        self.stdscr.addstr(self.y, 37, '─'*42 + '┤', DIM)
        self.y += 1

    def print_info_line(self, pairs, highlight = None, sep=" │ ", end="│", prefix="", dynaidx=None):
        x = 0
        infos = []

        for info in pairs:
            infolen = len(info[1]) + len(info[2])
            if infolen == 0:
                infos.append([" ".ljust(info[0]+2)])
            else:
                infos.append([info[1], info[2], " "*(info[0]-infolen)])

        self.stdscr.addstr(self.y, x, '│', DIM)
        x += 1

        i = 0
        for info in infos:
            self.stdscr.addstr(self.y, x, info[0] + " : ", DIM)
            x += len(info[0]) + 3

            if i == highlight:
                for e in info[1:]:
                    self.stdscr.addstr(self.y, x, e + " ", color(RED) + BOLD)
                    x += len(e) + 1            
            else:
                for e in info[1:]:
                    self.stdscr.addstr(self.y, x, e + " ")
                    x += len(e) + 1
            x -= 1
            self.stdscr.addstr(self.y, x, sep, DIM)
            x += len(sep)

            i += 1

        self.y += 1
    def refresh(self):
        self.y = 0
        self.stdscr.refresh()

class MonitorData:
    def __init__(self, workdir):
        self.workdir = workdir
        self.exec_avg = 0
        # self.slave_stats = []
        self.load_initial()

    def load_initial(self):
        self.cpu = psutil.cpu_times_percent(interval=0.01, percpu=False)
        self.mem = psutil.virtual_memory()
        self.cores_phys = psutil.cpu_count(logical=False)
        self.cores_virt = psutil.cpu_count(logical=True)
        self.stats = self.read_file("stats")
        print(self.stats)

        self.starttime = self.stats["start_time"]

        # add node information
        self.nodes = {}
        for metadata in glob.glob(self.workdir + "/metadata/node_*"):
            self.load_node(metadata)
        self.aggregate()

    def load_node(self, name):
        node_id = int(name.split("_")[-1])
        self.nodes[node_id] = self.read_file("metadata/node_%05d" % node_id)

    def runtime(self):
        return self.stats['run_time']

    def aggregate(self):
        self.aggregated = {
            "fav_states": {},
            "normal_states": {},
            "exit_reasons": {"regular": 0, "crash": 0, "kasan": 0, "timeout": 0},
            "last_found": {"regular": 0, "crash": 0, "kasan": 0, "timeout": 0}
        }

        for nid in self.nodes:
            node = self.nodes[nid]
            self.aggregated["exit_reasons"][node["info"]["exit_reason"]] += 1
            if node["info"]["exit_reason"] == "regular":
                states = self.aggregated["normal_states"]
                if len(node["fav_bits"]) > 0:
                    states = self.aggregated["fav_states"]
                nodestate = node["state"]["name"]
                states[nodestate] = states.get(nodestate, 0) + 1

            last_found = self.aggregated["last_found"][node["info"]["exit_reason"]]
            try:
                this_found = node["info"]["time"]
            except:
                pass
            if last_found < this_found:
                self.aggregated["last_found"][node["info"]["exit_reason"]] = this_found

    def load_slave(self, id):
        self.slave_stats[id] = self.read_file("slave_stats_%d" % id)

    def load_global(self):
        self.stats = self.read_file("stats")

    def node_size(self, nid):
        return self.nodes[nid]["payload_len"]

    def node_parent_id(self, nid):
        return self.nodes[nid]["info"]["parent"]    

    def num_slaves(self):
        return self.stats['num_slaves']
    
    def num_found(self, reason):
        return self.stats["findings"][reason]

    def num_found_unique(self, reason):
        return self.stats["unique_findings"][reason]

    def cycles(self):
        return self.stats.get("cycles", 0)

    def num_programs(self):
        return self.stats.get("programs")

    def num_unique_programs(self):
        return self.stats.get("unique_programs")

    def cpu_used(self):
        return self.cpu.user + self.cpu.system

    def now_program_id(self):
        return self.stats['now_program_id']

    def get_stage(self, method):
        return self.stats["stage"].get(method, 0)
    
    def get_yield(self, method):
        return self.stats["yield"].get(method, 0)

    def execs_p_sec_avg(self):
        return self.total_execs()/self.runtime()

    def total_execs(self):
        return  self.stats['total_execs']

    def time_since(self, reason):
        time_stamp = self.aggregated["last_found"][reason]
        if not time_stamp:
            return None
        return self.starttime + self.runtime() - time_stamp

    def bitmap_size(self):
        return 64 * 1024

    def bitmap_used(self):
        return self.stats["bytes_in_bitmap"]

    def paths_total(self):
        return self.stats["paths_total"]

    def paths_pending(self):
        return self.stats["paths_pending"]

    def favs_pending(self):
        return self.stats["favs_pending"]

    def fav_total(self):
        return self.stats["favs_total"]

    def density_program(self, pid):
        try:
            return self.nodes[pid]["map_density"]
        except:
            return 0

    def density_max(self):
        return 100.0 * float(self.bitmap_used()) / float(self.bitmap_size())

    def new_edges_on(self):
        new_edge = self.stats["new_edges_on"]
        if new_edge:
            return pnum(new_edge)
        else:
            return "n/a" 

    def update(self, pathname, filename):
        if "node_" in filename:
            self.load_node(pathname + "/" + filename)
            self.aggregate()
        elif "slave_stats" in filename:
            for i in range(0, self.num_slaves()):
                self.load_slave(i)
        elif filename == "stats":
            self.load_global()

    def read_file(self, name):
        retry = 4
        data = None
        while retry > 0:
            try:
                data = read_binary_file(self.workdir + "/" + name)
                break
            except:
                retry -= 1
        if data:
            return msgpack.unpackb(data, raw=False, strict_map_key=False)
        else:
            return None

class MonitorDrawer:
    def __init__(self, stdscr):
        global WORKDIR

        # mutex lock
        self.inf_mutex = Lock()
        self.key = Lock()

        # create pairs of forground and background colors
        curses.init_pair(WHITE, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(RED, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(GREEN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(YELLOW, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(BLUE, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(MAGENTA, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(CYAN, curses.COLOR_CYAN, curses.COLOR_BLACK)

        # set default color pair
        stdscr.bkgd(curses.color_pair(1))

        # create drawing interface
        self.inf = MonitorInterface(stdscr)
        self.stdscr = stdscr

        # create initial statistics
        self.finished = False
        self.data = MonitorData(WORKDIR)

        # create child threads for loop
        self.watcher = Thread(target=self.watch, args=(WORKDIR,))
        self.cpu_watcher = Thread(target=self.watch_cpu, args=())
        self.thread_loop = Thread(target=self.loop)

        # start watcher threads
        self.watcher.daemon = True
        self.watcher.start()
        self.cpu_watcher.daemon = True
        self.cpu_watcher.start()

        # start loop thread
        stdscr.refresh()
        self.thread_loop.start()
        self.thread_loop.join()
    
    def loop(self):
        while True:
            try:
                self.draw()
            finally:
                time.sleep(0.01)

    def watch(self, workdir):
        d = self.data
        mask = (inotify.constants.IN_MOVED_TO)
        self.inotify = inotify.adapters.Inotify()
        i = self.inotify
        i.add_watch(workdir, mask)
        i.add_watch(workdir + "/metadata/", mask)

        for event in i.event_gen(yield_nones=False):
            if self.finished:
                return
            self.inf_mutex.acquire()
            try:
                (_, type_names, path, filename) = event
                d.update(path, filename)
                self.draw()
            finally:
                self.inf_mutex.release()

    def watch_cpu(self):
        while True:
            if self.finished:
                return
            cpu_info = psutil.cpu_times_percent(interval=2, percpu=False)
            mem_info = psutil.virtual_memory()
            swap_info = psutil.swap_memory()
            self.inf_mutex.acquire()
            try:
                self.data.mem = mem_info
                self.data.cpu = cpu_info
                self.data.swap = swap_info
                self.draw()
            finally:
                self.inf_mutex.release()

    def draw(self):
        d = self.data
        self.key.acquire()
        
        self.inf.print_title()
        self.inf.print_guest_and_overall()

        self.inf.print_info_line([
            (50, "        run time", ptime(d.runtime())),
            (17, " cycles done", f"{d.cycles()}")])
        self.inf.print_info_line([
            (50, "   last new path", ptime(d.time_since("regular"))),
            (17, " total paths", f"{d.paths_total()}")])

        uniq_crashes = d.num_found_unique('crash')
        if uniq_crashes > 0:
            self.inf.print_info_line([
                (50, " last uniq crash", ptime(d.time_since("crash"))),
                (17, "uniq crashes", f"{pnum(uniq_crashes)}")], highlight=1)
        else:
            self.inf.print_info_line([
                (50, " last uniq crash", ptime(d.time_since("crash"))),
                (17, "uniq crashes", f"{pnum(uniq_crashes)}")])
        
        uniq_tmouts = d.num_found_unique('timeout')
        if uniq_tmouts > 0:
            self.inf.print_info_line([
                (50, " last uniq hangs", ptime(d.time_since("timeout"))),
                (17, "  uniq hangs", f"{pnum(d.num_found_unique('timeout'))}")], highlight=1)
        else:
            self.inf.print_info_line([
                (50, " last uniq hangs", ptime(d.time_since("timeout"))),
                (17, "  uniq hangs", f"{pnum(d.num_found_unique('timeout'))}")])


        self.inf.print_cycle_and_map()

        pid = d.now_program_id()
        self.inf.print_info_line([
            (33, "  now processing", pnum(pid)),
            (34, "   total edges", f"{d.bitmap_used()}")])
        self.inf.print_info_line([
            (33, "  total programs", f"{d.num_programs()} ({d.num_unique_programs()} unique)"),
            (34, "   map density", f"{pfloat(d.density_program(pid))}% / {pfloat(d.density_max())}%")])

        self.inf.print_stage_and_findings()
        
        now_trying = d.stats['now_trying']
        if d.paths_total() != 0:
            favered_percent = 100 * d.fav_total()/d.paths_total()
        else:
            favered_percent = 0
        self.inf.print_info_line([
            (33, "  now trying", f"{now_trying}"),
            (34, "favored paths", f"{d.fav_total()} ({pfloat(favered_percent)}%)")])
        
        if d.get_stage(now_trying) != 0:
            yield_percent = 100*d.get_yield(now_trying)/d.get_stage(now_trying)
        else:
            yield_percent = 0
        self.inf.print_info_line([
            (33, "stage yields", f"{pnum(d.get_yield(now_trying))}/{pnum(d.get_stage(now_trying))} ({pfloat(yield_percent)}%)"),
            (34, " new edges on", f"{d.new_edges_on()}")])

        if uniq_crashes > 0:
            self.inf.print_info_line([
                (33, " total execs", pnum(d.total_execs())),
                (34, "total crashes", f"{pnum(d.num_found('crash'))} ({uniq_crashes} unique)")], highlight=1)
        else:
            self.inf.print_info_line([
                (33, " total execs", pnum(d.total_execs())),
                (34, "total crashes", f"{pnum(d.num_found('crash'))} ({uniq_crashes} unique)")])

        if uniq_tmouts > 0:
            self.inf.print_info_line([
                (33, "  exec speed", f"{pnum(d.execs_p_sec_avg())}/sec"),
                (34, " total tmouts", f"{0} ({(pnum(d.num_found('timeout')))} unique)")], highlight=1)
        else:
            self.inf.print_info_line([
                (33, "  exec speed", f"{pnum(d.execs_p_sec_avg())}/sec"),
                (34, " total tmouts", f"{0} ({(pnum(d.num_found('timeout')))} unique)")])

        self.inf.print_strategy_and_geometry()

        self.inf.print_info_line([
            (50, "    insertIRP", f"{pnum(d.get_yield('insertIRP'))}/{pnum(d.get_stage('insertIRP'))}"),
            (17, "    level", f"{pnum(d.stats['max_level'])}")])
        self.inf.print_info_line([
            (50, "      swapIRP", f"{pnum(d.get_yield('swapIRP'))}/{pnum(d.get_stage('swapIRP'))}"),
            (17, " pend fav", f"{d.favs_pending()}")])
        self.inf.print_info_line([
            (50, "    mutateArg", f"{pnum(d.get_yield('mutateArg'))}/{pnum(d.get_stage('mutateArg'))}"),
            (17, "uniq prog", f"{d.num_unique_programs()}")])
        self.inf.print_info_line([
            (50, "  AFLdetermin", f"{pnum(d.get_yield('AFLdetermin'))}/{pnum(d.get_stage('AFLdetermin'))}"),
            (17, "   reload", pnum(d.stats["num_reload"]))])
        self.inf.print_info_line([
            (50, "       splice", f"{pnum(d.get_yield('splice'))}/{pnum(d.get_stage('splice'))}"),
            (17, "   reload", pnum(d.stats["num_reload"]))])
        self.inf.print_info_line([
            (50, "    removeIRP", f"{pnum(d.get_yield('removeIRP'))}/{pnum(d.get_stage('removeIRP'))}")])
        
        self.inf.print_last_two_line(d.cpu_used())

        self.inf.refresh()
        self.key.release()

def run(stdscr):
    try:
        MonitorDrawer(stdscr)
    except:
        return

# def main(workdir, driver):
#     global WORKDIR, SVCNAME
        
#     WORKDIR = workdir
#     SVCNAME = driver # todo - receive in args

#     signal.signal(signal.SIGINT, sigint_handler)

#     # delay for files to be generated
#     time.sleep(2)

#     curses.wrapper(run)

def main(stdscr):
    gui = MonitorDrawer(stdscr)
    gui.loop()


import locale
locale.setlocale(locale.LC_ALL, '')
code = locale.getpreferredencoding()

if len(sys.argv) < 2 or not os.path.exists(sys.argv[1]):
    print("Usage: " + sys.argv[0] + " <IRPT-workdir> <driver-name>")
    sys.exit(1)

WORKDIR = sys.argv[1]
SVCNAME = sys.argv[2]
signal.signal(signal.SIGINT, sigint_handler)

time.sleep(2)
try:
    curses.wrapper(main)
except FileNotFoundError as e:
    # Skip exception - typically just a fuzzer restart or wrong argv[1]
    print("Error reading from workdir. Exit.")