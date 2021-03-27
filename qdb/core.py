#!/usr/bin/env python3

import cmd
from functools import partial

from qiling import *
from qiling.const import *

from .frontend import context_printer, context_reg, context_asm, examine_mem
from .utils import parse_int, handle_bnj, is_thumb, CODE_END
from .const import *



class Qldbg(cmd.Cmd):

    def __init__(self, argv, rootfs, console=True, log_file=None, rr=False):

        self.ql_config = {
                "argv": argv,
                "rootfs": rootfs,
                "console": console,
                "log_file": log_file,
                "output": "default",
                }

        self._ql = None
        self.prompt = "(Qdb) "
        self.breakpoints = {}
        self._saved_states = None
        self.flow_trace = []
        if rr:
            self._states_list = [None]

        super().__init__()

    def parseline(self, line):
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
        build a new qiling instance for self._ql
        """
        if self._ql is not None:
            del self._ql

        self._ql = Qiling(**self.ql_config)

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

        if self._ql is None:
            self._get_new_ql()

        _hook = self._ql.hook_address(_bp_func, address)
        self.breakpoints.update({address: {"hook": _hook, "hitted": False, "temp": _is_temp}})

        if _is_temp == False:
            print("Breakpoint at 0x%08x" % address)

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

            print("hit breakpoint at 0x%08x" % _cur_addr)
            self.breakpoints.get(_cur_addr)["hitted"] = True

        self.do_context()
        self._ql.emu_stop()

    def do_run(self, *args):
        """
        launch qiling instance
        """

        if self._ql is None:
            self._get_new_ql()

        entry = self._ql.loader.entry_point

        self.run(entry)

    def run(self, address=None):
        """
        handle qiling instance launching
        """

        # for arm thumb mode
        if self._ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB) and is_thumb(self._ql.reg.cpsr):
            address |= 1


        self._ql.emu_start(address, 0)


    def do_backward(self, *args):

        if getattr(self, "_states_list", None) is None or self._states_list[-1] is None:
            print("there is no way back !!!")
        else:
            print("step backward ~")
            current_state_dicts = self._ql.save(cpu_context=True, mem=True, reg=False, fd=False)
            self._ql.restore(self._states_list.pop())
            self.do_context()


    def do_step(self, *args):
        """
        execute one instruction at a time
        """

        if self._ql is None:
            print("The program is not being run.")

        else:
            self._saved_states = dict(filter(lambda d: isinstance(d[0], str), self._ql.reg.save().items()))

            if getattr(self, "_states_list", None) is not None:
                self._states_list.append(self._ql.save(cpu_context=True, mem=True, reg=False, fd=False))

            _cur_addr = self._ql.reg.arch_pc

            next_stop = handle_bnj(self._ql, _cur_addr)

            if next_stop is CODE_END:
                return True

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

        entry = self._ql.loader.entry_point  # ld.so
        # entry = self._ql.loader.elf_entry # .text of binary

        if self._ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB) and entry & 1:
            entry -= 1

        if entry not in self.breakpoints.keys():
            self.set_breakpoint(entry, _is_temp=True)

        self.do_run()

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
        if self._ql is not None:
            _cur_addr = self._ql.reg.arch_pc
            print("continued from 0x%08x" % _cur_addr)

            self.run(_cur_addr)

    def do_examine(self, line):
        """
        Examine memory: x/FMT ADDRESS.
        format letter: o(octal), x(hex), d(decimal), u(unsigned decimal), t(binary), f(float), a(address), i(instruction), c(char), s(string) and z(hex, zero padded on the left)
        size letter: b(byte), h(halfword), w(word), g(giant, 8 bytes)
        e.g. x/4wx 0x41414141 , print 4 word size begin from address 0x41414141 in hex
        """

        _args = line.split()
        DEFAULT_FMT = ('x', 4, 1)

        if line.startswith("/"): # followed by format letter and size letter

            def get_fmt(text):
                def extract_count(t):
                    return "".join([s for s in t if s.isdigit()])

                f, s, c = DEFAULT_FMT
                if extract_count(text):
                    c = int(extract_count(text))

                for char in text.strip(str(c)):
                    if char in SIZE_LETTER.keys():
                        s = SIZE_LETTER.get(char)

                    elif char in FORMAT_LETTER:
                        f = char

                return (f, s, c)

            fmt, addr = line.strip("/").split()
            addr = parse_int(addr)
            fmt = get_fmt(fmt)

        elif len(_args) == 1: # only address
            addr = parse_int(_args[0])
            fmt = DEFAULT_FMT

        else:
            self.do_help("examine")
            return

        try:
            examine_mem(self._ql, addr, fmt)
        except:
            print("something went wrong")

    def do_context(self, *args):
        """
        show context information for current location
        """
        context_reg(self._ql, self._saved_states)
        self.flow_trace.append(self._ql.reg.arch_pc)
        context_asm(self._ql, self._ql.reg.arch_pc, self.flow_trace)

    def do_show(self, *args):
        """
        show some runtime informations
        """
        self._ql.mem.show_mapinfo()
        print("Qdb:", [(hex(idx), val) for idx, val in self.breakpoints.items()])
        print("internal:", [(hex(idx), val) for idx, val in self._ql._addr_hook.items()])

    def do_disassemble(self, address):
        """
        disassemble instructions from address specified
        """
        try:
            context_asm(self._ql, parse_int(address), 4)
        except:
            print("something went wrong")

    def do_shell(self, *command):
        """
        run python code,also a space between exclamation mark and command was necessary
        """
        try:
            print(eval(*command))
        except:
            print("something went wrong")

    def do_quit(self, *args):
        """
        exit Qdb
        """
        return True

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
