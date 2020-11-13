from common import rand

class IRP:
    def __init__(self, iocode, inlength, outlength, inbuffer=''):
        self.IoControlCode = iocode
        self.InputBufferLength = inlength
        self.OutputBufferLength = outlength
        if inbuffer == '':
            buf = []
            for _ in range(inlength):
                buf.append(rand.Intn(0xff))
            self.InputBuffer = buf
        else:
            self.InputBuffer = list(map(ord, inbuffer))