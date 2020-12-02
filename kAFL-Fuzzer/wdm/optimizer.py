import copy

class Optimizer:
    def __init__(self, q):
        self.q = q
        self.exec_results = []
    
    def clear(self):
        self.exec_results = []

    def add(self, program, exec_res, new_bytes, new_bits):
        self.exec_results.append([program, exec_res, new_bytes, new_bits])
    
    def __execute(self, irps, retry=0):
        if retry > 3:
            return None
        self.q.revert_driver()

        exec_res = None
        for irp in irps:
            exec_res = self.q.send_irp(irp)
            if exec_res.is_crash():
                print("Optimizer crashed")
                if not self.q.reload():
                    self.q.reload()
                return self.__execute(irps, retry + 1)
        return exec_res.apply_lut()

    def optimizable(self):
        return len(self.exec_results) > 0

    def optimize(self):
        optimized = []
        while len(self.exec_results):
            program, old_res, new_bytes, new_bits = self.exec_results.pop()

            # quick validation for funky case.
            
            self.q.turn_on_coverage_map()
            new_res = self.__execute(program.irps)
            self.q.turn_off_coverage_map()
            if not new_res:
                continue
            
            old_array = old_res.copy_to_array()
            new_array = new_res.copy_to_array()
            if new_array != old_array:
                continue
            program.bitmap = list(old_array)
            program.coverage_map = new_res.coverage_to_array()
            
            # program optimation
            program.exec_count = 0
            program.complexity += 1

            if len(program.irps) <= 1:
                optimized.append(program)
                continue

            # Remove irps not affecting coverage.
            i = 0
            exec_res = None
            while i < len(program.irps) and len(program.irps) > 1:
                exec_res = self.__execute(program.irps[:i] + program.irps[i+1:])
                if not exec_res:
                    continue
                
                valid = False
                for index in new_bytes.keys():
                    if exec_res.cbuffer[index] != new_bytes[index]:
                        valid = True
                        break
                if not valid:
                    for index in new_bits.keys():
                        if exec_res.cbuffer[index] != new_bits[index]:
                            valid = True
                            break
                if not valid:
                    del program.irps[i]
                else:
                    i += 1

            if len(program.irps):
                optimized.append(copy.deepcopy(program))

        self.exec_results = []  # clear
        return optimized