import copy

class Crasher:
    def __init__(self, q):
        self.q = q
        self.crash_programs = []

    def clear(self):
        self.crash_programs = []

    def add(self, program):
        self.crash_programs.append(copy.deepcopy(program))

    def reproducible(self):
        return len(self.crash_programs) > 0

    def reproduce(self):
        for program in self.crash_programs:
            self.q.reload_driver()
            for i in range(len(program.irps)):
                exec_res = self.q.send_irp(program.irps[i])
                if exec_res.is_crash():
                    print("Crash found!!")
                    self.q.reload()
                    program.save_to_file(exec_res.exit_reason)
                    break
        
        self.clear()