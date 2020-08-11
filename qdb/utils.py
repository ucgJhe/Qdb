#!/usr/bin/env python3
from qiling.const import *
from functools import partial



def dump_regs(ql, *args, **kwargs):
    
    if ql.archtype == QL_ARCH.MIPS:

        _reg_order = (
                "gp", "at", "v0", "v1",
                "a0", "a1", "a2", "a3",
                "t0", "t1", "t2", "t3",
                "t4", "t5", "t6", "t7",
                "t8", "t9", "sp", "s8",
                "s0", "s1", "s2", "s3",
                "s4", "s5", "s6", "s7",
                "ra", "k0", "k1", "pc",
                )

        return { reg_name: getattr(ql.reg, reg_name) for reg_name in _reg_order}

    elif ql.archtype == QL_ARCH.ARM:

        def _get_mode(bits):
            return {
                    0b10000: "User",
                    0b10001: "FIQ",
                    0b10010: "IRQ",
                    0b10011: "Supervisor",
                    0b10110: "Monitor",
                    0b10111: "Abort",
                    0b11010: "Hypervisor",
                    0b11011: "Undefined",
                    0b11111: "System",
                    }.get(bits & 0x00001f)

        def _get_thumb(bits):
            return "THUMB" if bits & 0x00000020 else "thumb"

        def _get_fiq(bits):
            return "FIQ" if bits & 0x00000040 else "fiq"

        def _get_irq(bits):
            return "IRQ" if bits & 0x00000080 else "irq"

        def _get_neg(bits):
            return "NEG" if bits & 0x80000000 else "neg"

        def _get_zero(bits):
            return "ZERO" if bits & 0x40000000 else "zero"

        def _get_carry(bits):
            return "CARRY" if bits & 0x20000000 else "carry"

        def _get_overflow(bits):
            return "OVERFLOW" if bits & 0x10000000 else "overflow"

        print(color.DARKCYAN, "r0: 0x%08x \t r1: 0x%08x \t r2: 0x%08x \t r3: 0x%08x" % (ql.reg.r0, ql.reg.r1, ql.reg.r2, ql.reg.r3), color.END, sep="")
        print(color.BLUE, "r4: 0x%08x \t r5: 0x%08x \t r6: 0x%08x \t r7: 0x%08x" % (ql.reg.r4, ql.reg.r5, ql.reg.r6, ql.reg.r7), color.END, sep="")
        print(color.RED, "r8: 0x%08x \t r9: 0x%08x \t r10: 0x%08x \t fp: 0x%08x" % (ql.reg.r8, ql.reg.r9, ql.reg.r10, ql.reg.r11), color.END, sep="")
        print(color.YELLOW, "r12: 0x%08x \t sp: 0x%08x \t lr: 0x%08x \t pc: 0x%08x" % (ql.reg.r12, ql.reg.sp, ql.reg.lr, ql.reg.pc), color.END, sep="")
        print(color.PURPLE, "c1_c0_2: 0x%08x \t c13_c0_3: 0x%08x \t fpexc: 0x%08x" % (ql.reg.c1_c0_2, ql.reg.c13_c0_3, ql.reg.fpexc), color.END, sep="")

        _mode = _get_mode(ql.reg.cpsr)
        _thumb = _get_thumb(ql.reg.cpsr)
        _fiq = _get_fiq(ql.reg.cpsr)
        _irq = _get_irq(ql.reg.cpsr)
        _neg = _get_neg(ql.reg.cpsr)
        _zero = _get_zero(ql.reg.cpsr)
        _carry = _get_carry(ql.reg.cpsr)
        _overflow = _get_overflow(ql.reg.cpsr)

        print(color.GREEN, "cpsr: 0x%08x => [%s Mode], [%s], [%s], [%s], [%s], [%s], [%s], [%s]" % (ql.reg.cpsr, _mode, _thumb, _fiq, _irq, _neg, _zero, _carry, _overflow), color.END, sep="")
        # print(color.GREEN, "cpsr: 0x%08x \t c1_c0_2: 0x%08x \t c13_c0_3: 0x%08x \t fpexc: 0x%08x" % (ql.reg.cpsr, ql.reg.c1_c0_2, ql.reg.c13_c0_3, ql.reg.fpexc), color.END, sep="")


# parse unsigned integer from string 
def parse_int(s):
    return int(s, 16) if s.startswith("0x") else int(s)


# check wether negative value or not
def is_negative(i):
    return i & (1 << 31)


# convert valu to signed
def signed_val(i):
    val = i

    if is_negative(val):
        val -= 1 << 32

    return val


# handle braches and jumps so we can set berakpoint properly
def handle_bnj(ql, cur_addr):
    return {
            QL_ARCH.MIPS: handle_bnj_mips,
            QL_ARCH.ARM:  handle_bnj_arm,
            }.get(ql.archtype)(ql, cur_addr)


def get_cpsr(bits):
    return (
            bits & 0x10000000, # V, overflow flag
            bits & 0x20000000, # C, carry flag
            bits & 0x40000000, # Z, zero flag
            bits & 0x80000000, # N, sign flag
            )


def handle_bnj_arm(ql, cur_addr):
    ARM_INST_SIZE  = 4

    md = ql.os.create_disassembler()
    _cur_ops = ql.mem.read(cur_addr, ARM_INST_SIZE)
    _tmp = md.disasm(_cur_ops, cur_addr)
    line = next(_tmp)

    # default breakpoint address if no jumps and branches here
    ret_addr = cur_addr + ARM_INST_SIZE

    if line.mnemonic.startswith('b'):
        V, C, Z, N = get_cpsr(ql.reg.cpsr)

        to_jump = {
                "b"  : (lambda *_: True),                    # unconditional jump
                "bl" : (lambda *_: True),                    # unconditional jump
                "beq": (lambda V, C, Z, N: Z),              # branch on equal
                "bne": (lambda V, C, Z, N: ~Z),             # branch on not equal
                "bls": (lambda V, C, Z, N: V ^ N),          # branch on less than
                "ble": (lambda V, C, Z, N: (Z | (N ^ V))),  # branch on less than or equal
                "bge": (lambda V, C, Z, N: ~(N ^ V)),       # branch on greater than or equal
                "bgt": (lambda V, C, Z, N: ~(Z | (N ^ V))), # branch on greater than
                "bhi": (lambda V, C, Z, N: ~Z & ~N),        # branch on higher
                }.get(line.mnemonic, None)(get_cpsr(ql.reg.cpsr))

        if to_jump:
            ret_addr = parse_int(line.op_str.strip('#'))

    return ret_addr


def handle_bnj_mips(ql, cur_addr):
    MIPS_INST_SIZE = 4

    def _read_reg(regs, _reg):
        return getattr(regs, _reg.strip('$').replace("fp", "s8"))

    read_reg_val = partial(_read_reg, ql.reg)
    md = ql.os.create_disassembler()
    _cur_ops = ql.mem.read(cur_addr, MIPS_INST_SIZE)
    _tmp = md.disasm(_cur_ops, cur_addr)
    line = next(_tmp)

    # default breakpoint address if no jumps and branches here
    ret_addr = cur_addr + MIPS_INST_SIZE

    if line.mnemonic.startswith('j') or line.mnemonic.startswith('b'):
        # make sure at least delay slot executed
        ret_addr += MIPS_INST_SIZE

        # get registers or memory address from op_str
        targets = [
                _read_reg(ql.reg, each)
                if '$' in each else parse_int(each)
                for each in line.op_str.split(", ")
                ]

        to_jump = {
                "j"       : (lambda _: True),             # uncontitional jump
                "jr"      : (lambda _: True),             # uncontitional jump
                "jal"     : (lambda _: True),             # uncontitional jump
                "jalr"    : (lambda _: True),             # uncontitional jump
                "b"       : (lambda _: True),             # unconditional branch
                "bl"      : (lambda _: True),             # unconditional branch
                "bal"     : (lambda _: True),             # unconditional branch
                "beq"     : (lambda r0, r1, _: r0 == r1), # branch on equal
                "bne"     : (lambda r0, r1, _: r0 != r1), # branch on not equal
                "blt"     : (lambda r0, r1, _: r0 < r1),  # branch on r0 less than r1
                "bgt"     : (lambda r0, r1, _: r0 > r1),  # branch on r0 greater than r1
                "ble"     : (lambda r0, r1, _: r0 <= r1), # brach on r0 less than or equal to r1
                "bge"     : (lambda r0, r1, _: r0 >= r1), # branch on r0 greater than or equal to r1
                "beqz"    : (lambda r, _: r == 0),        # branch on equal to zero
                "bnez"    : (lambda r, _: r != 0),        # branch on not equal to zero
                "bgtz"    : (lambda r, _: r > 0),         # branch on greater than zero
                "bltz"    : (lambda r, _: r < 0),         # branch on less than zero
                "bltzal"  : (lambda r, _: r < 0),         # branch on less than zero and link
                "blez"    : (lambda r, _: r <= 0),        # branch on less than or equal to zero
                "bgez"    : (lambda r, _: r >= 0),        # branch on greater than or equal to zero
                "bgezal"  : (lambda r, _: r >= 0),        # branch on greater than or equal to zero and link
                }.get(line.mnemonic, None)(*targets)

        if to_jump:
            # target address is always the rightmost one
            ret_addr = targets[-1]

    return ret_addr



if __name__ == "__main__":
    pass
