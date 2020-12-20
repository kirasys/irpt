import common.qemu_protocol as qemu_protocol

from wdm.program import MAX_BUFFER_LEN
from wdm.interface import interface_manager

def scan_page_fault(self, index):
    irp = self.cur_program.irps[index]

    if irp.InBufferLength != MAX_BUFFER_LEN:
        return

    oricmd = irp.Command
    irp.Command = qemu_protocol.SCAN_PAGE_FAULT
    if self.execute_irp(index):
        return True
    irp.Command = oricmd
