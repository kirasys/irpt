from common import rand

class IRP:
    def __init__(self, iocode, inlength, outlength, inbuffer=''):
        self.IoControlCode = iocode
        self.InBufferLength = inlength
        self.OutBufferLength = outlength
        if inbuffer == '':
            self.InBuffer = [0x7f] * self.InBufferLength
        else:
            self.InBuffer = list(map(ord, inbuffer))