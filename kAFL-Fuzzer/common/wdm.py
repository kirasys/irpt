import json

def to_range(rg):
    start, end = rg.split('-')
    return range(int(start), int(end) + 1 if end != 'inf' else 0xffffffff)

class InterfaceManager:
    def __init__(self):
        self.interface = {}
    
    def load(self, path):
        interface_json = json.loads(open(path, 'r').read())
        for constraint in interface_json:
            iocode = int(constraint["IoControlCode"], 16)
            inbuffer_ranges = list(map(to_range, constraint["InputBufferLength"]))
            outbuffer_ranges = list(map(to_range, constraint["OutputBufferLength"]))

            self.interface[iocode] = {"InputBufferRange": inbuffer_ranges, "OutputBufferRange": outbuffer_ranges}

    def size(self):
        return len(self.interface.keys())

    def satisfiable(self, iocode, length):
        inbuffer_ranges = self.interface[iocode]["InputBufferRange"]
        for rg in inbuffer_ranges:
            if length not in rg:
                return False
        return True
    
    def to_corpus(self):
        MAX_PAYLOAD_LEN = 0x1000
        for iocode in self.interface.keys():
            inbuffer_ranges = self.interface[iocode]["InputBufferRange"]

            length = 0
            for rg in inbuffer_ranges:
                length = max(length, rg.stop - 1)

            length = length if length <= MAX_PAYLOAD_LEN else MAX_PAYLOAD_LEN 
            yield (iocode, b'a' * length)

interface_manager = InterfaceManager()