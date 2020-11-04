import random

def oneOf(n):
    return random.randint(1, n) == 1
    
def nOutOf(n, outOf):
    v = random.randint(1, outOf)
    return v <= n

def Intn(n):
    return random.randint(0, n-1)