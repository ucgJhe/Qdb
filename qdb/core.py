#!/usr/bin/env python3

from __future__ import annotations
from typing import Optional

import cmd

from qiling import Qiling
from qiling.const import QL_ARCH, QL_VERBOSE

from .frontend import context_reg, context_asm, examine_mem
from .utils import parse_int, handle_bnj, is_thumb, CODE_END
from .const import color
from .breakpoint import Breakpoint, TempBreakpoint


class Qldbg(cmd.Cmd):

    def __init__(
            self: Qldbg,
            argv: [str],
            rootfs: str,
            console: bool = True,
            rr: bool = False,
            verbose: QL_VERBOSE = QL_VERBOSE.DEFAULT,
            log_file: Optional[str] = None,
            ) -> Qldbg:

        self.ql_config = {
                "argv": argv,
                "rootfs": rootfs,
                "console": console,
                "verbose": verbose,
                "log_file": log_file,
                }

        self._ql = None
        self._rr = rr
        self.prompt = "(Qdb) "
        self.breakpoints = {}
        self.states_list = []
        self._saved_reg_dump = None

        super().__init__()

    def parseline(self: Qldbg, line: str, /, *args, **kargs) -> [Optional[str], Optional[str], str]:
        """Parse the line into a command name and a string containing
        the arguments.  Returns a tuple containing (command, args, line).
        'command' and 'args' may be None if the line couldn't be parsed.
        """
        line = line.strip()
        if not line:
            return None, None, line
        elif line[0] == '?':
            line = 'help ' + line[1:]
        elif line.startswith('!'):
            if hasattr(self, 'do_shell'):
                line = 'shell ' + line[1:]
            else:
                return None, None, line
        i, n = 0, len(line)
        while i < n and line[i] in self.identchars: i = i+1
        cmd, arg = line[:i], line[i:].strip()
        return cmd, arg, line

    def interactive(self: Qldbg, /, *args, **kwargs) -> None:
        self.cmdloop()

    def emptyline(self: Qldbg, /, *args, **kwargs) -> Optional[str]:
        """
        repeat last command
        """
        if (lastcmd := getattr(self, "do_" + self.lastcmd, None)):
            return lastcmd()

    def _get_new_ql(self: Qldbg, /, *args, **kwargs) -> None:
        """
        build a new qiling instance for self._ql
        """
        del self._ql
        self._ql = Qiling(**self.ql_config)

    def del_breakpoint(self: Qldbg, bp: Breakpoint) -> None:
        """
        handle internal breakpoint removing operation
        """
        if self.breakpoints.pop(bp.address, None) is not None:
            bp.hook.remove()

    def set_breakpoint(self: Qldbg, address: str, is_temp: bool = False) -> None:
        """
        handle internal breakpoint adding operation
        """

        if is_temp is False:
            print(f"{color.CYAN}[+] Breakpoint at 0x{address:08x}{color.END}")

        bp = TempBreakpoint(address) if is_temp else Breakpoint(address)

        if getattr(self, "_ql", None) is None:
            self._get_new_ql()

        bp.hook = self._ql.hook_address(self._breakpoint_handler, bp.address)
        self.breakpoints.update({address: bp})


    def _breakpoint_handler(self: Qldbg, ql: Qiling) -> None:
        """
        handle all breakpoints
        """
        bp = self.breakpoints.get(ql.reg.arch_pc)

        if isinstance(bp, TempBreakpoint):  # remove temporary breakpoint
            self.del_breakpoint(bp)

        else:
            if bp.hitted:
                return

            print(f"{color.CYAN}[+] hit breakpoint at 0x{bp.address:08x}{color.END}")
            bp.hitted = True

        self.do_context()
        self._ql.stop()
        self.states_list.append(self._save_cur_state())

    def _save_cur_state(self: Qldbg, cpu_context: bool = True, mem: bool = True, reg: bool = False, fd: bool = False):
        return self._ql.save(cpu_context=cpu_context, mem=mem, reg=reg, fd=fd)

    def do_run(self: Qldbg, /, *args, **kwargs) -> None:
        """
        launch qiling instance
        """

        if getattr(self, "_ql", None) is None:
            self._get_new_ql()

        entry = self._ql.loader.entry_point

        self.run(entry)

    def run(self: Qldbg, address: Optional[str] = None, /, *args, **kwargs) -> None:
        """
        handle qiling instance launching
        """

        if getattr(self, "_ql", None) is None:
            self._get_new_ql()

        # for arm thumb mode
        if self._ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB) and is_thumb(self._ql.reg.cpsr):
            address |= 1

        self._ql.run(address)

    def do_backward(self, *args):
        """
        step backward if possible
        """

        if len(self.states_list) == 0 or self._rr is False:
            print(f"{color.RED}[!] there is no way back !!!{color.END}")

        else:
            print(f"{color.CYAN}[+] step backward ~{color.END}")
            self._ql.restore(self.states_list.pop())
            self.do_context()

    def do_step(self, *args):
        """
        execute one instruction at a time
        """

        if getattr(self, "_ql", None) is None:
            print("{color.RED}[!] The program is not being run.{color.END}")

        else:
            self._saved_reg_dump = dict(filter(lambda r: isinstance(r[0], str), self._ql.reg.save().items()))

            if self._rr:
                self.states_list.append(self._save_cur_state())

            self._get_new_ql()
            self._ql.restore(self.states_list.pop())

            _cur_addr = self._ql.reg.arch_pc
            next_stop = handle_bnj(self._ql, _cur_addr)
            # print(f"next_stop: {hex(next_stop)}")

            if next_stop is CODE_END:
                return True

            # whether bp placed already
            if self.breakpoints.get(next_stop, None):
                self.breakpoints.get(next_stop).hitted = False

            else:
                self.set_breakpoint(next_stop, is_temp=True)

            self.run(_cur_addr)

    def do_start(self, *args):
        """
        pause at entry point by setting a temporary breakpoint on it
        """
        if getattr(self, "_ql", None) is None:
            self._get_new_ql()

        entry = self._ql.loader.entry_point  # ld.so
        # entry = self._ql.loader.elf_entry # .text of binary

        if self._ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB) and entry & 1:
            entry -= 1

        if entry not in self.breakpoints.keys():
            self.set_breakpoint(entry, is_temp=True)

        self.do_run()

    def do_breakpoint(self: Qldbg, address: str, /, *args, **kwargs) -> None:
        """
        set breakpoint on specific address
        """
        if address:
            try:
                baddr = parse_int(address)
                self.set_breakpoint(baddr)
            except:
                print(f"{color.RED}[!] something went wrong ...{color.END}")

    def do_continue(self: Qldbg, /, *args, **kwargs) -> None:
        """
        continue execution till next breakpoint or the end
        """
        if self._ql is not None:
            _cur_addr = self._ql.reg.arch_pc
            print(f"continued from 0x{_cur_addr:08x}")

            self.run(_cur_addr)
        else:
            print(f"{color.RED}[!] there is nowhere to be continued {color.END}")

    def do_examine(self: Qldbg, line: str, /, *args, **kwargs) -> None:
        """
        Examine memory: x/FMT ADDRESS.
        format letter: o(octal), x(hex), d(decimal), u(unsigned decimal), t(binary), f(float), a(address), i(instruction), c(char), s(string) and z(hex, zero padded on the left)
        size letter: b(byte), h(halfword), w(word), g(giant, 8 bytes)
        e.g. x/4wx 0x41414141 , print 4 word size begin from address 0x41414141 in hex
        """

        try:
            if not examine_mem(self._ql, line):
                self.do_help("examine")
        except:
            print(f"{color.RED}[!] something went wrong ...{color.END}")

    def do_context(self: Qldbg, /, *args, **kwargs) -> None:
        """
        show context information for current location
        """
        context_reg(self._ql, self._saved_reg_dump)
        context_asm(self._ql, self._ql.reg.arch_pc)

    def do_show(self: Qldbg, /, *args, **kwargs) -> None:
        """
        show some runtime information
        """
        self._ql.mem.show_mapinfo()
        print("Qdb:", [(hex(idx), val) for idx, val in self.breakpoints.items()])
        print("internal:", [(hex(idx), val) for idx, val in self._ql._addr_hook.items()])

    def do_disassemble(self: Qldbg, address: str, /, *args, **kwargs) -> None:
        """
        disassemble instructions from address specified
        """
        try:
            context_asm(self._ql, parse_int(address), 4)
        except:
            print(f"{color.RED}[!] something went wrong ...{color.END}")

    def do_shell(self: Qldbg, /, *command: str, **kwargs) -> None:
        """
        run python code,also a space between exclamation mark and command was necessary
        """
        try:
            print(eval(*command))
        except:
            print(f"{color.RED}[!] something went wrong ...{color.END}")

    def do_quit(self: Qldbg, /, *args, **kwargs) -> bool:
        """
        exit Qdb
        """
        return True

    def do_test(self: Qldbg, /, *args, **kwargs):
        self.do_start()

        while True:
            self.do_step()

    do_r = do_run
    do_q = do_quit
    do_x = do_examine
    do_c = do_continue
    do_b = do_breakpoint
    do_si = do_step
    do_rsi = do_backward
    do_dis = do_disassemble


if __name__ == "__main__":
    pass
