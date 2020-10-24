import os
import sys
import json
import struct

p32 = lambda x : struct.pack('<I', x)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage : %s interface.json output_path" % sys.argv[0])
        sys.exit(0)

    interface_file = sys.argv[1]
    output_path = sys.argv[2]

    with open(interface_file) as f:
        interfaces = json.load(f)['interfaces']
        print(interfaces)
        for i in range(len(interfaces)):
            IoControlCode = interfaces[i]['IoControlCode']
            InputBufferSize = interfaces[i]['InputBufferSize']
            open(os.path.join(output_path, 'code_payload%04d' % i), 'wb').write(p32(IoControlCode) + b'a'*InputBufferSize)