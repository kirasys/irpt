from wdm.program import MAX_BUFFER_LEN
from wdm.interface import interface_manager

def scan_page_fault(self, index):
    irp = self.cur_program.irps[index]

    if irp.InBufferLength < MAX_BUFFER_LEN and irp.InBufferLength < 0x1000:
        return

    # When it is unable to change the length.
    if "InBufferLength" in interface_manager[irp.IoControlCode] or \
        "OutBufferLength" in interface_manager[irp.IoControlCode]:
        return

    orilen = irp.InBufferLength

    # padding to 0x1000
    irp.InBuffer += [0x61] * 0x1000
    irp.InBuffer = irp.InBuffer[:0x1000]
    irp.InBufferLength = 0x1000

    # upto 0x20000
    for _ in range(0, 0x20):
        if interface_manager.satisfiable(irp) and self.execute_irp(index):
            return True
        irp.InBuffer += [0x61] * 0x1000
        irp.InBufferLength += 0x1000

    irp.InBuffer = irp.InBuffer[:orilen]
    irp.InBufferLength = orilen
