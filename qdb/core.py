import cmd

from qiling import *
from qiling.const import *
from functools import partial
from .frontend import context_printer, context_reg, context_asm
from .utils import parse_int, handle_bnj



class Qldbg(cmd.Cmd):

    def __init__(self, filename, rootfs, console=True, log_dir=None):

        self.ql_config = {
                "filename": filename,
                "rootfs": rootfs,
                "console": console,
                "log_dir": log_dir,
                "output": "default",
                }

        self.ql = None
        self.prompt = "(Qdb) "
        self.breakpoints = {}

        super().__init__()

    def interactive(self):
        self.cmdloop()

    def emptyline(self, *args):
        """
        repeat last command
        """
        _lastcmd = getattr(self, "do_" + self.lastcmd, None)
        if _lastcmd:
            return _lastcmd()

    def _get_new_ql(self):
        """
        build a new qiling instance for self.ql
        """
        if self.ql is not None:
            del self.ql

        self.ql = Qiling(**self.ql_config)

    def del_breakpoint(self, address):
        """
        handle internal breakpoint removing operation
        """
        _bp = self.breakpoints.pop(address, None)
        if _bp:
            _bp["hook"].remove()

    def set_breakpoint(self, address, _is_temp=False):
        """
        handle internal breakpoint adding operation
        """
        _bp_func = partial(self._breakpoint_handler, _is_temp=_is_temp)

        if self.ql is None:
            self._get_new_ql()

        _hook = self.ql.hook_address(_bp_func, address)
        self.breakpoints.update({address: {"hook": _hook, "hitted": False, "temp": _is_temp}})

        if _is_temp == False:
            self.ql.nprint("Breakpoint at 0x%08x" % address)

    def _breakpoint_handler(self, ql, _is_temp=False):
        """
        handle all breakpoints
        """
        _cur_addr = ql.reg.arch_pc

        if _is_temp: # remove temporary breakpoint
            self.del_breakpoint(_cur_addr)
        else:
            if self.breakpoints.get(_cur_addr)["hitted"]:
                return

            self.ql.nprint("hit breakpoint at 0x%08x" % _cur_addr)
            self.breakpoints.get(_cur_addr)["hitted"] = True

        self.do_context()
        self.ql.emu_stop()

    def run(self, address=None):
        """
        handle qiling instance launching
        """
        if not address:
            address = self.ql.loader.entry_point

        self.ql.emu_start(address, 0)

    def do_context(self, *args):
        """
        show context information for current location
        """
        context_reg(self.ql)
        context_asm(self.ql, self.ql.reg.arch_pc, 4)

    def do_run(self, *args):
        """
        launch qiling instance
        """
        if self.ql is None:
            self._get_new_ql()

        self.run()

    def do_show(self, *args):
        """
        show some runtime informations
        """
        self.ql.mem.show_mapinfo()
        print("Qdb:", [(hex(idx), val) for idx, val in self.breakpoints.items()])
        print("internal:", [(hex(idx), val) for idx, val in self.ql._addr_hook.items()])

    def do_step(self, *args):
        """
        execute one instruction at a time
        """

        if self.ql is None:
            print("The program is not being run.")

        else:
            _cur_addr = self.ql.reg.arch_pc
            next_stop = handle_bnj(self.ql, _cur_addr)

            # whether bp placed already
            if self.breakpoints.get(next_stop, None):
                self.breakpoints.get(next_stop)["hitted"] = False

            else:
                self.set_breakpoint(next_stop, _is_temp=True)

            self.run(_cur_addr)
            

    def do_start(self, *args):
        """
        pause at entry point by setting a temporary breakpoint on it
        """
        self._get_new_ql()
        _elf_entry = self.ql.loader.elf_entry   # .text of binary
        self.set_breakpoint(_elf_entry, _is_temp=True)
        self.run()

    def do_breakpoint(self, address):
        """
        set breakpoint on specific address
        """
        if address:
            baddr = parse_int(address)
            self.set_breakpoint(baddr)

    def do_continue(self, *args):
        """
        continue execution till next breakpoint or the end
        """
        if self.ql is not None:
            _cur_addr = self.ql.reg.arch_pc
            self.ql.nprint("continued from 0x%08x" % _cur_addr)
            self.run(_cur_addr)

    def do_examine(self, xaddr=None, size=4):
        """
        examine data of address in qiling memory
        """
        if xaddr:
            _xaddr = parse_int(xaddr)
            self.ql.nprint("0x%08x:\t0x%08x" % (_xaddr, self.ql.unpack(self.ql.mem.read(_xaddr, size))))
        else:
            self.ql.nprint("need address to examine")

    def do_disassemble(self, address):
        """
        disassemble instructions from address specified
        """
        context_asm(self.ql, parse_int(address), 4)

    def do_shell(self, *command):
        """
        run python code,also a space between exclamation mark and command was necessary
        """
        print(eval(*command))

    def do_quit(self):
        """
        exit Qdb
        """
        return True

    do_r = do_run
    do_s = do_step
    do_q = do_quit
    do_x = do_examine
    do_c = do_continue
    do_b = do_breakpoint
    do_dis = do_disassemble
    


if __name__ == "__main__":
    pass
