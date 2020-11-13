import json

def to_range(rg):
    start, end = rg.split('-')
    return range(int(start), int(end) + 1 if end != 'inf' else 0xffffffff)

class Interface:
    def __init__(self):
        self.interface = {}

    def __getitem__(self, key):
        return self.interface[key]

    def load(self, path):
        interface_json = json.loads(open(path, 'r').read())
        for constraint in interface_json:
            iocode = int(constraint["IoControlCode"], 16)
            inbuffer_ranges = list(map(to_range, constraint["InputBufferLength"]))
            outbuffer_ranges = list(map(to_range, constraint["OutputBufferLength"]))

            self.interface[iocode] = {"InputBufferRange": inbuffer_ranges, "OutputBufferRange": outbuffer_ranges, "exec_count": 0}
        
    def get_all_code(self):
        return self.interface.keys()

interface_manager = Interface()