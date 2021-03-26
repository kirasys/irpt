#!/usr/bin/env python3
#
# Copyright 2020-2021 Namjun Jo (kirasys@theori.io)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from common import rand

class IRP:
    def __init__(self, iocode, inlength, outlength, inbuffer='', command=0):
        self.IoControlCode = iocode
        self.InBufferLength = inlength
        self.OutBufferLength = outlength
        if inbuffer == '':
            self.InBuffer = [0xFF] * self.InBufferLength
        else:
            self.InBuffer = list(map(ord, inbuffer))
        
        self.Command = command