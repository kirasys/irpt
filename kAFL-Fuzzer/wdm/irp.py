class IRP:
    def __init__(self, iocode, inlength, outlength, inbuffer=''):
        self.IoControlCode = iocode
        self.InputBufferLength = inlength
        self.OutputBufferLength = outlength
        if inbuffer == '':
            self.InputBuffer = [ord('a')] * self.InputBufferLength
        else:
            self.InputBuffer = list(map(ord, inbuffer))