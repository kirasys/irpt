import json
from common.util import MAX_RANGE_VALUE

def to_range(rg):
    start, end = rg.split('-')
    return range(int(start), int(end) + 1 if end != 'inf' else MAX_RANGE_VALUE)

class Interface:
    def __init__(self):
        self.interface = {}

    def __getitem__(self, key):
        return self.interface[key]

    def load(self, path):
        interface_json = json.loads(open(path, 'r').read())
        for constraint in interface_json:
            iocode = int(constraint["IoControlCode"], 16)
            inbuffer_ranges = list(map(to_range, constraint["InBufferLength"]))
            outbuffer_ranges = list(map(to_range, constraint["OutBufferLength"]))

            self.interface[iocode] = {"InBufferRange": inbuffer_ranges, "OutBufferRange": outbuffer_ranges, "exec_count": 0}
        
    def get_all_code(self):
        return self.interface.keys()
    
    def satisfiable(self, irp):
        inbuffer_ranges = self.interface[irp.IoControlCode]["InBufferRange"]
        for rg in inbuffer_ranges:
            if len(irp.InBuffer) not in rg:
                return False
        return True

interface_manager = Interface()