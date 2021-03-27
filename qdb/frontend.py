#!/usr/bin/env python3

import math, copy, os
from contextlib import contextmanager

from qiling.const import QL_ARCH

from .utils import dump_regs, get_arm_flags, disasm
from .const import *


# read data from memory of qiling instance
def examine_mem(ql, addr, fmt):

    def unpack(bs, sz):
        return {
                1: lambda x: x[0],
                2: ql.unpack16,
                4: ql.unpack32,
                8: ql.unpack64,
                }.get(sz)(bs)

    ft, sz, ct = fmt

    if ft == "i":

        for offset in range(addr, addr+ct*4, 4):
            line = disasm(ql, offset)
            if line:
                print("0x{:x}: {}\t{}".format(line.address, line.mnemonic, line.op_str))

        print()

    else:
        lines = 1 if ct <= 4 else math.ceil(ct / 4)

        mem_read = [ql.mem.read(addr+(offset*sz), sz) for offset in range(ct)]

        for line in range(lines):
            offset = line * sz * 4
            print("0x{:x}:\t".format(addr+offset), end="")

            idx = line * ql.archbit // 8
            for each in mem_read[idx:idx+(ql.archbit // 8)]:
                data = unpack(each, sz)
                prefix = "0x" if ft in ("x", "a") else ""
                pad = '0' + str(sz*2) if ft in ('x', 'a', 't') else ''
                ft = ft.lower() if ft in ("x", "o", "b", "d") else ft.lower().replace("t", "b").replace("a", "x")

                print("{}{{:{}{}}}\t".format(prefix, pad, ft).format(data), end="")

            print()

# get terminal window height and width
def get_terminal_size():
    return map(int, os.popen('stty size', 'r').read().split())


# try to read data from ql memory
def _try_read(ql, address, size):
    try:
        result = ql.mem.read(address, size)
    except:
        result = None

    return result


# divider printer
@contextmanager
def context_printer(ql, field_name, ruler="="):
    _height, _width = get_terminal_size()
    print(field_name, ruler * (_width - len(field_name) - 1))
    yield
    print(ruler * _width)


def context_reg(ql, saved_states=None, *args, **kwargs):

    # context render for registers
    with context_printer(ql, "[Registers]"):

        _cur_regs = dump_regs(ql)

        _colors = (color.DARKCYAN, color.BLUE, color.RED, color.YELLOW, color.GREEN, color.PURPLE, color.CYAN, color.WHITE)

        if ql.archtype == QL_ARCH.MIPS:

            _cur_regs.update({"fp": _cur_regs.pop("s8")})

            if saved_states is not None:
                _saved_states = copy.deepcopy(saved_states)
                _saved_states.update({"fp": _saved_states.pop("s8")})
                _diff = [k for k in _cur_regs if _cur_regs[k] != _saved_states[k]]

            else:
                _diff = None

            lines = ""
            for idx, r in enumerate(_cur_regs, 1):
                line = "{}{}: 0x{{:08x}} {}\t".format(_colors[(idx-1) // 4], r, color.END)

                if _diff and r in _diff:
                    line = "{}{}".format(color.UNDERLINE, color.BOLD) + line

                if idx % 4 == 0 and idx != 32:
                    line += "\n"

                lines += line

            print(lines.format(*_cur_regs.values()))

        elif ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):

            _cur_regs.update({"sl": _cur_regs.pop("r10")})
            _cur_regs.update({"fp": _cur_regs.pop("r11")})
            _cur_regs.update({"ip": _cur_regs.pop("r12")})

            if saved_states is not None:
                _saved_states = copy.deepcopy(saved_states)
                _saved_states.update({"sl": _saved_states.pop("r10")})
                _saved_states.update({"fp": _saved_states.pop("r11")})
                _saved_states.update({"ip": _saved_states.pop("r12")})
                _diff = [k for k in _cur_regs if _cur_regs[k] != _saved_states[k]]

            else:
                _diff = None

            lines = ""
            for idx, r in enumerate(_cur_regs, 1):
                line = "{}{:}: 0x{{:08x}} {}\t".format(_colors[(idx-1) // 4], r, color.END)

                if _diff and r in _diff:
                    line = "{}{}".format(color.UNDERLINE, color.BOLD) + line

                if idx % 4 == 0:
                    line += "\n"

                lines += line

            print(lines.format(*_cur_regs.values()))
            print(color.GREEN, "[{cpsr[mode]} mode], Thumb: {cpsr[thumb]}, FIQ: {cpsr[fiq]}, IRQ: {cpsr[irq]}, NEG: {cpsr[neg]}, ZERO: {cpsr[zero]}, Carry: {cpsr[carry]}, Overflow: {cpsr[overflow]}".format(cpsr=get_arm_flags(ql.reg.cpsr)), color.END, sep="")

    # context render for Stack
    with context_printer(ql, "[Stack]", ruler="-"):

        for idx in range(8):
            _addr = ql.reg.arch_sp + idx * 4
            _val = ql.mem.read(_addr, ql.archbit // 8)
            print("$sp+0x%02x|[0x%08x]=> 0x%08x" % (idx*4, _addr, ql.unpack(_val)), end="")

            try: # try to deference wether its a pointer
                _deref = ql.mem.read(_addr, ql.archbit // 8)
            except:
                _deref = None

            if _deref:
                print(" => 0x%08x" % ql.unpack(_deref))


def print_asm(ql, ins):
    fmt = (ins.address, ins.mnemonic.ljust(6), ins.op_str)
    if ql.reg.arch_pc == ins.address:
        print("PC ==>  0x%x\t%s %s" % fmt)
    else:
        print("\t0x%x\t%s %s" % fmt)


def context_asm(ql, address, *args, **kwargs):

    with context_printer(ql, field_name="[Code]"):

        # assembly before current location

        past_list = []

        if ql.archtype in (QL_ARCH.MIPS, QL_ARCH.ARM, QL_ARCH.ARM_THUMB):

            line = disasm(ql, address-0x10)

        while line:
            if line.address == address:
                break

            addr = line.address + line.size
            line = disasm(ql, addr)

            if not line:
                break

            past_list.append(line)

        # print four insns before current location
        for line in past_list[:-1][:4]:
            print_asm(ql, line)

        # assembly for current location

        cur_ins = disasm(ql, address)
        print_asm(ql, cur_ins)

        # assembly after current location

        forward_insn_size = cur_ins.size
        for _ in range(5):
            forward_insn = disasm(ql, address+forward_insn_size)
            if forward_insn:
                print_asm(ql, forward_insn)
                forward_insn_size += forward_insn.size
