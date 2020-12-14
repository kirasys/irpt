from wdm.program import MAX_BUFFER_LEN
from wdm.interface import interface_manager

def scan_page_fault(self, index):
    irp = self.cur_program.irps[index]

    if irp.InBufferLength != MAX_BUFFER_LEN:
        return

    irp.InBufferLength |= 0xFF000000
    if self.execute_irp(index):
        return True
    irp.InBufferLength &= 0xFFFFFF
