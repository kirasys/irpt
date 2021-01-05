import common.qemu_protocol as qemu_protocol

from wdm.program import MAX_BUFFER_LEN
from wdm.interface import interface_manager

def scan_page_fault(self, index):
    self.cur_program.set_state('pagefault')
    irp = self.cur_program.irps[index]

    if irp.InBufferLength != MAX_BUFFER_LEN:
        return

    oricmd = irp.Command
    irp.Command = qemu_protocol.SCAN_PAGE_FAULT
    if self.execute_irp(index):
        return True
    irp.Command = oricmd

def resolve_dependency(self):
    self.cur_program.set_state('dependency')
    orilen = len(self.cur_program.irps)

    for uniq_program in self.database.get_unique_programs():
        self.cur_program.irps += uniq_program.irps
        self.q.reload_driver()
        for i in range(len(self.cur_program.irps)):
            if self.execute_irp(i):
                return True

        self.cur_program.irps = self.cur_program.irps[:orilen]