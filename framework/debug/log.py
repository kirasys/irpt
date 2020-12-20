'''
Basic logging routine for IRPT Fuzzer.
'''

PREFIX = {
    'EXCEPT':'\033[1;31m[EXCEPT]\033[0m ',
    'ERROR':'\033[1;31m[ERROR]\033[0m ',
    'WARN':'\033[1;31m[WARNING]\033[0m ',
    'CRASH':'\033[1;31m[CRASH]\033[0m ',
    'PROCESS':' \033[1;33m[PROC]\033[0m ',
    'PROGRAM':' \033[1;32m[PROG]\033[0m     ',
    'DEBUG':'\033[1;33m[DEBUG]\033[0m ',
    'IRP':'  \033[1;34m[IRP]\033[0m   ',
    }

ENABLE_LOG = True

def disable_log():
    global ENABLE_LOG
    ENABLE_LOG = False

def log(msg, label="DEBUG"):
    data = PREFIX[label] + msg
    if ENABLE_LOG == True:
        print(data) 