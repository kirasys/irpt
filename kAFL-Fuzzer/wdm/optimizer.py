class Optimizer:
    def __init__(self, q):
        self.q = q
        self.optimizer_queue = []
        self.bitmap_index_to_fav_node = {}

    def clear(self):
        self.optimizer_queue = []

    def add(self, program, exec_res, new_bytes, new_bits):
        self.optimizer_queue.append([program, exec_res, new_bytes, new_bits])
    
    def __execute(self, program, reload=False):
        if reload:
            self.q.reload_driver()
        else:
            self.q.revert_driver()

        exec_res = None
        for irp in program.irps:
            exec_res = self.q.send_irp(irp)
            if exec_res.is_crash():
                return None

        return exec_res.apply_lut()

    def optimize(self):
        optimized = []
        while len(self.optimizer_queue):
            program, old_res, new_bytes, new_bits = self.optimizer_queue.pop()

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
                program.clear_fav_bits(write=False)
                self.update_best_input_for_bitmap_entry(program, exec_res)
                optimized.append(program.clone_with_bitmap(list(exec_res.copy_to_array())))

        self.optimizer_queue = []  # clear
        return optimized

    def should_overwrite_old_entry(self, index, val, node):
        entry = self.bitmap_index_to_fav_node.get(index)
        if not entry:
            return True, None
        old_node, old_val = entry
        more_bits = val > old_val
        # better_score = (val == old_val and node.get_fav_factor() < old_node.get_fav_factor())
        if more_bits: # or better_score:
            return True, old_node
        return False, None

    def update_best_input_for_bitmap_entry(self, new_node, bitmap):
        changed_nodes = set()
        for (index, val) in enumerate(bitmap.cbuffer):
            if val == 0x0:
                continue
            overwrite, old_node = self.should_overwrite_old_entry(index, val, new_node)
            if overwrite:
                self.bitmap_index_to_fav_node[index] = (new_node, val)
                new_node.add_fav_bit(index, write=False)
                changed_nodes.add(new_node)
                if old_node:
                    old_node.remove_fav_bit(index, write=False)
                    changed_nodes.add(old_node)
                    self.statistics.event_node_remove_fav_bit(old_node)
        for node in changed_nodes:
            node.write_metadata()