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

            self.interface[iocode] = {"InBufferRange": inbuffer_ranges, "OutBufferRange": outbuffer_ranges}
            if len(inbuffer_ranges) == 1 and len(inbuffer_ranges[0]) == 1:
                self.interface[iocode]["InBufferLength"] = inbuffer_ranges[0][0]
            if len(outbuffer_ranges) == 1 and len(outbuffer_ranges[0]) == 1:
                self.interface[iocode]["OutBufferLength"] = outbuffer_ranges[0][0]

    def count(self):
        return len(self.get_all_code())

    def get_all_code(self):
        return self.interface.keys()
    
    def satisfiable(self, irp):
        inbuffer_ranges = self.interface[irp.IoControlCode]["InBufferRange"]
        for rg in inbuffer_ranges:
            if len(irp.InBuffer) not in rg:
                return False
        
        outbuffer_ranges = self.interface[irp.IoControlCode]["OutBufferRange"]
        for rg in outbuffer_ranges:
            if irp.OutBufferLength not in rg:
                return False
        return True

interface_manager = Interface()