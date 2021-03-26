# Copyright 2020-2021 Namjun Jo (kirasys@theori.io)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import random

def oneOf(n):
    return random.randint(1, n) == 1
    
def nOutOf(n, outOf):
    v = random.randint(1, outOf)
    return v <= n

def Intn(n):
    return random.randint(0, n)

def Index(n):
    return random.randint(0, n-1)