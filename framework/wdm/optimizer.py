import copy

class Optimizer:
    def __init__(self, q, statistics):
        self.q = q
        self.statistics = statistics

        self.optimizer_queue = []
        self.bitmap_index_to_fav_program = {}
    
    def clear(self):
        self.optimizer_queue = []

    def add(self, program, exec_res, new_bytes, new_bits):
        self.optimizer_queue.append([program, exec_res, new_bytes, new_bits])
    
    def __execute(self, irps, retry=0):
        if retry > 3:
            return None
        self.q.reload_driver()

        exec_res = None
        for irp in irps:
            exec_res = self.q.send_irp(irp)
            if exec_res.is_crash():
                self.q.reload()
                self.statistics.event_reload()
                return self.__execute(irps, retry + 1)
        return exec_res.apply_lut()

    def optimizable(self):
        return len(self.optimizer_queue) > 0

    def optimize(self):
        optimized = []
        while len(self.optimizer_queue):
            program, old_res, new_bytes, new_bits = self.optimizer_queue.pop()

            # quick validation for funky case.
            self.q.enable_coverage_map()
            new_res = self.__execute(program.irps)
            self.q.disable_coverage_map()
            if not new_res:
                continue
            
            old_array = old_res.copy_to_array()
            new_array = new_res.copy_to_array()
            if new_array != old_array:
                continue
            program.bitmap = list(old_array)
            program.coverage_map = new_res.coverage_to_array()

            # Program optimation
            # Remove irps which is not affecting coverage.
            while len(program.irps) > 1:
                exec_res = self.__execute(program.irps[len(program.irps)//2:])
                if not exec_res:
                    continue

                dependent = False
                for index in new_bytes.keys():
                    if exec_res.cbuffer[index] != new_bytes[index]:
                        dependent = True
                        break
                if not dependent:
                    for index in new_bits.keys():
                        if exec_res.cbuffer[index] != new_bits[index]:
                            dependent = True
                            break
                if dependent:
                    break
                program.irps = program.irps[len(program.irps)//2:]

            if len(program.irps) <= 1:
                optimized.append(program)
                continue
            
            i = 0
            exec_res = None
            while i < len(program.irps) and len(program.irps) > 1:
                exec_res = self.__execute(program.irps[:i] + program.irps[i+1:])
                if not exec_res:
                    continue
                
                dependent = False
                for index in new_bytes.keys():
                    if exec_res.cbuffer[index] != new_bytes[index]:
                        dependent = True
                        break
                if not dependent:
                    for index in new_bits.keys():
                        if exec_res.cbuffer[index] != new_bits[index]:
                            dependent = True
                            break
                if not dependent:
                    del program.irps[i]
                else:
                    i += 1

            if len(program.irps):
                optimized.append(copy.deepcopy(program))

        self.optimizer_queue = []  # clear
        return optimized