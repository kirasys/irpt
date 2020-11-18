from common import rand

class IRP:
    def __init__(self, iocode, inlength, outlength, inbuffer=''):
        self.IoControlCode = iocode
        self.InBufferLength = inlength
        self.OutBufferLength = outlength
        if inbuffer == '':
            buf = []
            for _ in range(inlength):
                buf.append(rand.Intn(0xff))
            self.InBuffer = buf
        else:
            self.InBuffer = list(map(ord, inbuffer))