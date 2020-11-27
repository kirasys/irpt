class Optimizer:
    def __init__(self, q):
        self.q = q
        self.exec_results = []
    
    def clear(self):
        self.exec_results = []

    def add(self, program, exec_res, new_bytes, new_bits):
        self.exec_results.append([program, exec_res, new_bytes, new_bits])
    
    def __execute(self, program, reload=False, retry=0):
        if retry > 3:
            return None

        if reload:
            self.q.reload_driver()
        else:
            self.q.revert_driver()

        exec_res = None
        for irp in program.irps:
            exec_res = self.q.send_irp(irp)
            if exec_res.is_crash():
                print("crashed")
                if not self.q.reload():
                    self.q.reload()
                return self.__execute(program, reload, retry + 1)
        return exec_res.apply_lut()

    def optimizable(self):
        return len(self.exec_results) > 0

    def optimize(self):
        optimized = []
        while len(self.exec_results):
            program, old_res, new_bytes, new_bits = self.exec_results.pop()

            # quick validation for funky case.
            old_array = old_res.copy_to_array()
            new_res = self.__execute(program, reload=True)
            if not new_res:
                continue
            new_array = new_res.copy_to_array()
            if new_array != old_array:
                continue
            program.bitmap = list(old_array)

            # program optimation
            program.exec_count = 0
            program.complexity += 1

            if len(program.irps) <= 1:
                optimized.append(program)
                continue

            # dedulicate same coverage irp.
            i = 0
            exec_res = None
            while i < len(program.irps) and len(program.irps) > 1:
                test_program = program.clone_with_irps(program.irps[:i] + program.irps[i+1:])
                exec_res = self.__execute(test_program, reload=False)
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
                optimized.append(program.clone_with_bitmap(list(exec_res.copy_to_array())))

        self.exec_results = []  # clear
        return optimized