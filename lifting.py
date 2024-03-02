import struct
from functools import partial
from binaryninja.enums import LowLevelILFlagCondition
from binaryninja.lowlevelil import LowLevelILLabel, LowLevelILFunction, LowLevelILOperation, ILRegister, ILFlag, LLIL_TEMP

from enum import Enum, auto

class ArithmeticLogicalOpcode(Enum):
    ADD = auto()
    ADC = auto()
    SUB = auto()
    SBC = auto()
    AND = auto()
    XOR = auto()
    OR = auto()
    CMP = auto()
    INC = auto()
    DEC = auto()
    DAA = auto()
    DPL = auto()

def decode_unimplemented(length, data, addr, il: LowLevelILFunction):
    il.append(il.unimplemented())
    return length

def decode_nop(data, addr, il: LowLevelILFunction):
    il.append(il.nop())
    return 1

def decode_call_unconditional_a16(data, addr, il: LowLevelILFunction):
    dest_address = struct.unpack("<H", data[1:3])[0]
    il.append(il.call(il.const_pointer(2, dest_address)))
    return 3

def decode_rst(dest_address, data, addr, il: LowLevelILFunction):
    il.append(il.call(il.const_pointer(2, dest_address)))
    return 1

def decode_jp_hl(data, addr, il: LowLevelILFunction):
    il.append(il.jump(il.reg(2, 'HL')))
    return 1

def decode_jp_unconditional_a16(data, addr, il: LowLevelILFunction):
    dest_address = struct.unpack("<H", data[1:3])[0]
    label = il.get_label_for_address(il.arch, dest_address)
    if label:
        il.append(il.goto(label))
    else:
        il.append(il.jump(il.const_pointer(2, dest_address)))
    return 3

def decode_jp_conditional_a16(data, addr, il: LowLevelILFunction):
    instruction_length = 3
    next_instruction_addr = addr + instruction_length
    dest_address = struct.unpack("<H", data[1:3])[0]
    opcode = data[0]

    if opcode == 0xc2:
        cond = il.flag_condition(LowLevelILFlagCondition.LLFC_NE)
    elif opcode == 0xca:
        cond = il.flag_condition(LowLevelILFlagCondition.LLFC_E)
    elif opcode == 0xd2:
        cond = il.not_expr(0, il.flag('c'))
    elif opcode == 0xda:
        cond = il.flag('c')
    else:
        return None
    # if there are no flags to process here then stop, we'll reach this another way if it's real code
    if not cond:
        return None

    true_label = il.get_label_for_address(il.arch, dest_address)
    false_label = il.get_label_for_address(il.arch, next_instruction_addr)

    if true_label and false_label:
        il.append(il.if_expr(cond, true_label, false_label))
    else:
        new_true_label = LowLevelILLabel()
        new_false_label = LowLevelILLabel()
        il.append(il.if_expr(cond, new_true_label, new_false_label))
        il.mark_label(new_true_label)
        if true_label:
            goto_or_jmp = il.goto(true_label)
        else:
            goto_or_jmp = il.jump(il.const_pointer(2, dest_address))
        il.append(goto_or_jmp)
        il.mark_label(new_false_label)
    
    return instruction_length

def decode_jr_unconditional_r8(data, addr, il: LowLevelILFunction):
    instruction_length = 2
    next_instruction_addr = addr + instruction_length
    offset = struct.unpack("<B", data[1:2])[0]
    dest_address = next_instruction_addr + offset
    label = il.get_label_for_address(il.arch, dest_address)
    if label:
        il.append(il.goto(label))
    else:
        il.append(il.jump(il.const_pointer(2, dest_address)))
    return instruction_length

def decode_call_conditional_a16(data, addr, il: LowLevelILFunction):
    instruction_length = 3
    dest_address = struct.unpack("<H", data[1:3])[0]
    opcode = data[0]

    if opcode == 0xc4:
        cond = il.flag_condition(LowLevelILFlagCondition.LLFC_NE)
    elif opcode == 0xcc:
        cond = il.flag_condition(LowLevelILFlagCondition.LLFC_E)
    elif opcode == 0xd4:
        cond = il.not_expr(0, il.flag('c'))
    elif opcode == 0xdc:
        cond = il.flag('c')
    else:
        return None
    # if there are no flags to process here then stop, we'll reach this another way if it's real code
    if not cond:
        return None

    # we skip the label stuff from the relative jump because a call has to hit an address?
    new_true_label = LowLevelILLabel()
    new_false_label = LowLevelILLabel()
    il.append(il.if_expr(cond, new_true_label, new_false_label))
    il.mark_label(new_true_label)
    il.append(il.call(il.const_pointer(2, dest_address)))
    il.mark_label(new_false_label)
    
    return instruction_length

def decode_jr_conditional_r8(data, addr, il: LowLevelILFunction):
    instruction_length = 2
    next_instruction_addr = addr + instruction_length
    offset = struct.unpack("<B", data[1:2])[0]
    dest_address = next_instruction_addr + offset
    opcode = data[0]

    if opcode == 0x20:
        cond = il.flag_condition(LowLevelILFlagCondition.LLFC_NE)
    elif opcode == 0x28:
        cond = il.flag_condition(LowLevelILFlagCondition.LLFC_E)
    elif opcode == 0x30:
        cond = il.not_expr(0, il.flag('c'))
    elif opcode == 0x38:
        cond = il.flag('c')
    else:
        return None
    # if there are no flags to process here then stop, we'll reach this another way if it's real code
    if not cond:
        return None

    true_label = il.get_label_for_address(il.arch, dest_address)
    false_label = il.get_label_for_address(il.arch, next_instruction_addr)

    if true_label and false_label:
        il.append(il.if_expr(cond, true_label, false_label))
    else:
        new_true_label = LowLevelILLabel()
        new_false_label = LowLevelILLabel()
        il.append(il.if_expr(cond, new_true_label, new_false_label))
        il.mark_label(new_true_label)
        if true_label:
            goto_or_jmp = il.goto(true_label)
        else:
            goto_or_jmp = il.jump(il.const_pointer(2, dest_address))
        il.append(goto_or_jmp)
        il.mark_label(new_false_label)
    
    return instruction_length

def decode_ret_conditional(data, addr, il: LowLevelILFunction):
    instruction_length = 1
    opcode = data[0]

    if opcode == 0xc0:
        cond = il.flag_condition(LowLevelILFlagCondition.LLFC_NE)
    elif opcode == 0xc8:
        cond = il.flag_condition(LowLevelILFlagCondition.LLFC_E)
    elif opcode == 0xd0:
        cond = il.not_expr(0, il.flag('c'))
    elif opcode == 0xd8:
        cond = il.flag('c')
    else:
        return None
    # if there are no flags to process here then stop, we'll reach this another way if it's real code
    if not cond:
        return None
    
    new_true_label = LowLevelILLabel()
    new_false_label = LowLevelILLabel()
    il.append(il.if_expr(cond, new_true_label, new_false_label))
    il.mark_label(new_true_label)
    il.append(il.ret(il.pop(2)))
    il.mark_label(new_false_label)
    
    return instruction_length

def decode_ret_unconditional(data, addr, il: LowLevelILFunction):
    il.append(il.ret(il.pop(2)))
    return 1

def read_reg8_or_hl_pointer(reg, il: LowLevelILFunction):
    if reg in ['B', 'C', 'D', 'E', 'H', 'L', 'A']:
        return il.reg(1, reg)
    elif reg == "(HL)":
        return il.load(1, il.reg(2, 'HL'))
    else:
        raise Exception("Invalid reg8: %s" % reg)

def set_reg8_or_hl_pointer(reg, value, il: LowLevelILFunction):
    if reg in ['B', 'C', 'D', 'E', 'H', 'L', 'A']:
        return il.set_reg(1, reg, value)
    elif reg == "(HL)":
        return il.store(1, il.reg(2, 'HL'), value)
    else:
        raise Exception("Invalid reg8: %s" % reg)

def load_reg16_pointer(reg, il: LowLevelILFunction):
    return il.load(1, il.reg(2, reg))

def store_reg16_pointer(reg, value, il: LowLevelILFunction):
    return il.store(1, il.reg(2, reg), value)

def decode_cp_d8(data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<B', data[1:2])[0]
    il.append(il.sub(1, il.reg(1, 'A'), il.const(1, arg), '*'))
    return 2

def decode_arithmetic_logical_reg16(dest_reg, src_reg, opcode, data, addr, il: LowLevelILFunction):
    if opcode == ArithmeticLogicalOpcode.INC:
        expression = il.add(2, il.reg(2, src_reg), il.const(2, 1))
    elif opcode == ArithmeticLogicalOpcode.DEC:
        expression = il.sub(2, il.reg(2, src_reg), il.const(2, 1))
    elif opcode == ArithmeticLogicalOpcode.ADD:
        expression = il.add(2, il.reg(2, dest_reg), il.reg(2, src_reg), 'nhc')
    else:
        il.append(il.unimplemented())
        return 1
    
    il.append(il.set_reg(2, dest_reg, expression))
    return 1

def decode_arithmetic_logical_8bit(reg, opcode, data, addr, il: LowLevelILFunction):
    if reg == "d8":
        instruction_size = 2
        src = il.const(1, struct.unpack('<B', data[1:2])[0])
    else:
        src = read_reg8_or_hl_pointer(reg, il)
        instruction_size = 1
    dest_reg = il.reg(1, 'A')
    if opcode == ArithmeticLogicalOpcode.ADD:
        expression = il.add(1, dest_reg, src, '*')
    elif opcode == ArithmeticLogicalOpcode.ADC:
        expression = il.add_carry(1, dest_reg, src, il.flag("c"), '*')
    elif opcode == ArithmeticLogicalOpcode.SUB or opcode == ArithmeticLogicalOpcode.CMP:
        expression = il.sub(1, dest_reg, src, '*')
    elif opcode == ArithmeticLogicalOpcode.SBC:
        expression = il.sub_borrow(1, dest_reg, src, il.flag("c"), '*')
    elif opcode == ArithmeticLogicalOpcode.AND:
        expression = il.and_expr(1, dest_reg, src, '*')
    elif opcode == ArithmeticLogicalOpcode.XOR:
        expression = il.xor_expr(1, dest_reg, src, '*')
    elif opcode == ArithmeticLogicalOpcode.OR:
        expression = il.or_expr(1, dest_reg, src, '*')
    elif opcode == ArithmeticLogicalOpcode.INC:
        expression = il.add(1, src, il.const(1, 1), 'znh')
    elif opcode == ArithmeticLogicalOpcode.DEC:
        expression = il.sub(1, src, il.const(1, 1), 'znh')
    else:
        il.append(il.unimplemented())
        return instruction_size
    
    if opcode == ArithmeticLogicalOpcode.INC or opcode == ArithmeticLogicalOpcode.DEC:
        il.append(set_reg8_or_hl_pointer(reg, expression, il))
    elif opcode == ArithmeticLogicalOpcode.CMP:
        il.append(expression)
    else:
        il.append(il.set_reg(1, 'A', expression))

    return instruction_size

def decode_set_hl_pointer_d8(data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<B', data[1:2])[0]
    il.append(store_reg16_pointer('HL', il.const(1, arg), il))
    return 2

def decode_set_reg_d8(reg, data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<B', data[1:2])[0]
    il.append(il.set_reg(1, reg, il.const(1, arg)))
    return 2

def decode_set_reg_reg8(dest, src, data, addr, il: LowLevelILFunction):
    src_reg = read_reg8_or_hl_pointer(src, il)
    il.append(il.set_reg(1, dest, src_reg))
    return 1

def decode_set_a_a16(data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<H', data[1:3])[0]
    il.append(il.set_reg(1, 'A', il.load(1, il.const_pointer(2, arg))))
    return 3

def decode_set_reg8_reg16_pointer(dest_reg, src_reg, data, addr, il: LowLevelILFunction):
    if src_reg in ('BC', 'DE', 'HL'):
        il.append(il.set_reg(1, dest_reg, load_reg16_pointer(src_reg, il)))
    elif src_reg == 'HL+':
        il.append(il.set_reg(1, dest_reg, load_reg16_pointer('HL', il)))
        il.append(il.set_reg(2, 'HL', il.add(2, il.reg(2, 'HL'), il.const(2, 1))))
    elif src_reg == 'HL-':
        il.append(il.set_reg(1, dest_reg, load_reg16_pointer('HL', il)))
        il.append(il.set_reg(2, 'HL', il.sub(2, il.reg(2, 'HL'), il.const(2, 1))))
    return 1

def decode_set_reg16_pointer_reg8(dest_reg, src_reg, data, addr, il: LowLevelILFunction):
    if dest_reg in ('BC', 'DE', 'HL'):
        il.append(store_reg16_pointer(dest_reg, il.reg(1, src_reg), il))
    elif dest_reg == 'HL+':
        il.append(store_reg16_pointer('HL', il.reg(1, src_reg), il))
        il.append(il.set_reg(2, 'HL', il.add(2, il.reg(2, 'HL'), il.const(2, 1))))
    elif dest_reg == 'HL-':
        il.append(store_reg16_pointer('HL', il.reg(1, src_reg), il))
        il.append(il.set_reg(2, 'HL', il.sub(2, il.reg(2, 'HL'), il.const(2, 1))))
    return 1

def decode_set_reg_d16(reg, data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<H', data[1:3])[0]
    il.append(il.set_reg(2, reg, il.const(2, arg)))
    return 3

def decode_set_hl_sp_plus_d8(data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<B', data[1:2])[0]
    sum = il.add(2, il.reg(2, 'SP'), il.const(2, arg))
    il.append(il.set_reg(2, 'HL', sum))
    return 1

def decode_set_sp_hl(data, addr, il: LowLevelILFunction):
    il.append(il.set_reg(2, 'SP', il.reg(2, 'HL')))
    return 1

def decode_set_a16_a(data, addr, il: LowLevelILFunction):
    dest_address = struct.unpack('<H', data[1:3])[0]
    il.append(il.store(1, il.const_pointer(2, dest_address), il.reg(1, 'A')))
    return 3

def decode_set_a16_sp(data, addr, il: LowLevelILFunction):
    dest_address = struct.unpack('<H', data[1:3])[0]
    il.append(il.store(2, il.const_pointer(2, dest_address), il.reg(2, 'SP')))
    return 3

def decode_set_a8_a(data, addr, il: LowLevelILFunction):
    dest_address = 0xFF00 + struct.unpack('<B', data[1:2])[0]
    dest_pointer = il.const_pointer(2, dest_address)
    il.append(il.store(1, dest_pointer, il.reg(1, 'A')))
    return 2

def decode_set_c_a(data, addr, il: LowLevelILFunction):
    dest_pointer = il.add(2, il.const_pointer(2, 0xFF00), il.zero_extend(2, il.reg(1, 'C')))
    il.append(il.store(1, dest_pointer, il.reg(1, 'A')))
    return 2

def decode_set_a_a8(data, addr, il: LowLevelILFunction):
    src_address = 0xFF00 + struct.unpack('<B', data[1:2])[0]
    src_pointer = il.const_pointer(2, src_address)
    il.append(il.set_reg(1, 'A', il.load(1, src_pointer)))
    return 2

def decode_set_a_c(data, addr, il: LowLevelILFunction):
    src_pointer = il.add(2, il.const_pointer(2, 0xFF00), il.zero_extend(2, il.reg(1, 'C')))
    il.append(il.set_reg(1, 'A', il.load(1, src_pointer)))
    return 2

def decode_push_reg16(reg, data, addr, il: LowLevelILFunction):
    il.append(il.push(2, il.reg(2, reg)))
    return 1

def decode_pop_reg16(reg, data, addr, il: LowLevelILFunction):
    il.append(il.set_reg(2, reg, il.pop(2)))
    return 1

def decode_push_af(data, addr, il: LowLevelILFunction):
    il.append(il.push(1, il.reg(1, 'A')))
    # push flags
    flags = il.or_expr(1,
        il.or_expr(1,
            il.flag_bit(1, 'z', 7),
            il.flag_bit(1, 'n', 6),
        ),
        il.or_expr(1,
            il.flag_bit(1, 'h', 5),
            il.flag_bit(1, 'c', 4),
        )
    )
    il.append(il.push(1, flags))
    return 1

def decode_pop_af(data, addr, il: LowLevelILFunction):
    # pop flags
    il.append(il.expr(LowLevelILOperation.LLIL_SET_REG,
        LLIL_TEMP(0),
        il.pop(1),
        size = 1
    ))
    temp0 = il.expr(LowLevelILOperation.LLIL_REG, LLIL_TEMP(0), 1)
    il.append(il.set_flag('z', il.test_bit(1, temp0, il.const(1, 1<<7))))
    il.append(il.set_flag('n', il.test_bit(1, temp0, il.const(1, 1<<6))))
    il.append(il.set_flag('h', il.test_bit(1, temp0, il.const(1, 1<<5))))
    il.append(il.set_flag('c', il.test_bit(1, temp0, il.const(1, 1<<4))))

    il.append(il.set_reg(1, 'A', il.pop(1)))
    return 1

def decode_rla(data, addr, il: LowLevelILFunction):
    il.append(il.set_reg(1, 'A', il.rotate_left(1, il.reg(1, 'A'), il.const(1, 1), 'nhc')))
    il.append(il.set_flag('z', il.const(1, 0)))
    return 1

def decode_rra(data, addr, il: LowLevelILFunction):
    il.append(il.set_reg(1, 'A', il.rotate_right(1, il.reg(1, 'A'), il.const(1, 1), 'nhc')))
    il.append(il.set_flag('z', il.const(1, 0)))
    return 1

def decode_rlca(data, addr, il: LowLevelILFunction):
    il.append(il.set_reg(1, 'A', il.rotate_left_carry(1, il.reg(1, 'A'), il.const(1, 1), il.flag('c'), 'nhc')))
    il.append(il.set_flag('z', il.const(1, 0)))
    return 1

def decode_rrca(data, addr, il: LowLevelILFunction):
    il.append(il.set_reg(1, 'A', il.rotate_right_carry(1, il.reg(1, 'A'), il.const(1, 1), il.flag('c'), 'nhc')))
    il.append(il.set_flag('z', il.const(1, 0)))
    return 1

def decode_rl_reg8(reg, data, addr, il: LowLevelILFunction):
    il.append(set_reg8_or_hl_pointer('A', il.rotate_left(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 1), '*'), il))
    return 2

def decode_rr_reg8(reg, data, addr, il: LowLevelILFunction):
    il.append(set_reg8_or_hl_pointer('A', il.rotate_right(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 1), '*'), il))
    return 2

def decode_rlc_reg8(reg, data, addr, il: LowLevelILFunction):
    il.append(set_reg8_or_hl_pointer('A', il.rotate_left_carry(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 1), il.flag('c'), '*'), il))
    return 2

def decode_rrc_reg8(reg, data, addr, il: LowLevelILFunction):
    il.append(set_reg8_or_hl_pointer('A', il.rotate_right_carry(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 1), il.flag('c'), '*'), il))
    return 2

def decode_sla_reg8(reg, data, addr, il: LowLevelILFunction):
    il.append(set_reg8_or_hl_pointer('A', il.shift_left(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 1), '*'), il))
    return 2

def decode_sra_reg8(reg, data, addr, il: LowLevelILFunction):
    il.append(set_reg8_or_hl_pointer('A', il.arith_shift_right(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 1), '*'), il))
    return 2

def decode_srl_reg8(reg, data, addr, il: LowLevelILFunction):
    il.append(set_reg8_or_hl_pointer('A', il.logical_shift_right(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 1), '*'), il))
    return 2

def decode_swap_reg8(reg, data, addr, il: LowLevelILFunction):
    # swapping nybbles so that's the same as a rotate 4
    il.append(set_reg8_or_hl_pointer('A', il.rotate_right(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 4), '*'), il))
    return 2

def decode_test_bit(arg, reg, data, addr, il: LowLevelILFunction):
    il.append(il.set_flag('z', il.test_bit(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 1<<arg))))
    il.append(il.set_flag('n', il.const(1, 0)))
    il.append(il.set_flag('h', il.const(1, 1)))
    return 2

def decode_set_bit(arg, reg, data, addr, il: LowLevelILFunction):
    il.append(set_reg8_or_hl_pointer(reg, il.or_expr(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 1<<arg)), il))
    return 2

def decode_reset_bit(arg, reg, data, addr, il: LowLevelILFunction):
    # make mask with XOR and then AND to clear bit
    il.append(set_reg8_or_hl_pointer(reg, il.and_expr(1, read_reg8_or_hl_pointer(reg, il), il.const(1, 0xFF ^ (1<<arg))), il))
    return 2

def decode_cpl(data, addr, il: LowLevelILFunction):
    il.append(il.set_reg(1, 'A', il.xor_expr(1, il.reg(1, 'A'), il.const(1, 0xFF))))
    il.append(il.set_flag('n', il.const(1, 1)))
    il.append(il.set_flag('h', il.const(1, 1)))
    return 1

def decode_scf(data, addr, il: LowLevelILFunction):
    il.append(il.set_flag('c', il.const(1, 1)))
    il.append(il.set_flag('n', il.const(1, 0)))
    il.append(il.set_flag('h', il.const(1, 0)))
    return 1

def decode_ccf(data, addr, il: LowLevelILFunction):
    il.append(il.set_flag('c', il.xor_expr(1, il.flag('c'), il.const(1, 1))))
    il.append(il.set_flag('n', il.const(1, 0)))
    il.append(il.set_flag('h', il.const(1, 0)))
    return 1

def decode_add_sp_r8(data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<B', data[1:2])[0]
    dest_reg = il.reg(2, 'SP')
    expression = il.add(2, dest_reg, il.sign_extend(2, il.const(1, arg)), 'nhc')
    il.append(il.set_reg(2, 'SP', expression))
    il.append(il.set_flag('z', il.const(1, 0)))
    return 2


handlers_by_opcode_cbprefixed = {
    0x0: partial(decode_rlc_reg8, 'B'),
    0x1: partial(decode_rlc_reg8, 'C'),
    0x2: partial(decode_rlc_reg8, 'D'),
    0x3: partial(decode_rlc_reg8, 'E'),
    0x4: partial(decode_rlc_reg8, 'H'),
    0x5: partial(decode_rlc_reg8, 'L'),
    0x6: partial(decode_rlc_reg8, '(HL)'),
    0x7: partial(decode_rlc_reg8, 'A'),
    0x8: partial(decode_rrc_reg8, 'B'),
    0x9: partial(decode_rrc_reg8, 'C'),
    0xa: partial(decode_rrc_reg8, 'D'),
    0xb: partial(decode_rrc_reg8, 'E'),
    0xc: partial(decode_rrc_reg8, 'H'),
    0xd: partial(decode_rrc_reg8, 'L'),
    0xe: partial(decode_rrc_reg8, '(HL)'),
    0xf: partial(decode_rrc_reg8, 'A'),
    0x10: partial(decode_rl_reg8, 'B'),
    0x11: partial(decode_rl_reg8, 'C'),
    0x12: partial(decode_rl_reg8, 'D'),
    0x13: partial(decode_rl_reg8, 'E'),
    0x14: partial(decode_rl_reg8, 'H'),
    0x15: partial(decode_rl_reg8, 'L'),
    0x16: partial(decode_rl_reg8, '(HL)'),
    0x17: partial(decode_rl_reg8, 'A'),
    0x18: partial(decode_rr_reg8, 'B'),
    0x19: partial(decode_rr_reg8, 'C'),
    0x1a: partial(decode_rr_reg8, 'D'),
    0x1b: partial(decode_rr_reg8, 'E'),
    0x1c: partial(decode_rr_reg8, 'H'),
    0x1d: partial(decode_rr_reg8, 'L'),
    0x1e: partial(decode_rr_reg8, '(HL)'),
    0x1f: partial(decode_rr_reg8, 'A'),
    0x20: partial(decode_sla_reg8, 'B'),
    0x21: partial(decode_sla_reg8, 'C'),
    0x22: partial(decode_sla_reg8, 'D'),
    0x23: partial(decode_sla_reg8, 'E'),
    0x24: partial(decode_sla_reg8, 'H'),
    0x25: partial(decode_sla_reg8, 'L'),
    0x26: partial(decode_sla_reg8, '(HL)'),
    0x27: partial(decode_sla_reg8, 'A'),
    0x28: partial(decode_sra_reg8, 'B'),
    0x29: partial(decode_sra_reg8, 'C'),
    0x2a: partial(decode_sra_reg8, 'D'),
    0x2b: partial(decode_sra_reg8, 'E'),
    0x2c: partial(decode_sra_reg8, 'H'),
    0x2d: partial(decode_sra_reg8, 'L'),
    0x2e: partial(decode_sra_reg8, '(HL)'),
    0x2f: partial(decode_sra_reg8, 'A'),
    0x30: partial(decode_swap_reg8, 'B'),
    0x31: partial(decode_swap_reg8, 'C'),
    0x32: partial(decode_swap_reg8, 'D'),
    0x33: partial(decode_swap_reg8, 'E'),
    0x34: partial(decode_swap_reg8, 'H'),
    0x35: partial(decode_swap_reg8, 'L'),
    0x36: partial(decode_swap_reg8, '(HL)'),
    0x37: partial(decode_swap_reg8, 'A'),
    0x38: partial(decode_srl_reg8, 'B'),
    0x39: partial(decode_srl_reg8, 'C'),
    0x3a: partial(decode_srl_reg8, 'D'),
    0x3b: partial(decode_srl_reg8, 'E'),
    0x3c: partial(decode_srl_reg8, 'H'),
    0x3d: partial(decode_srl_reg8, 'L'),
    0x3e: partial(decode_srl_reg8, '(HL)'),
    0x3f: partial(decode_srl_reg8, 'A'),
    0x40: partial(decode_test_bit, 0, 'B'),
    0x41: partial(decode_test_bit, 0, 'C'),
    0x42: partial(decode_test_bit, 0, 'D'),
    0x43: partial(decode_test_bit, 0, 'E'),
    0x44: partial(decode_test_bit, 0, 'H'),
    0x45: partial(decode_test_bit, 0, 'L'),
    0x46: partial(decode_test_bit, 0, '(HL)'),
    0x47: partial(decode_test_bit, 0, 'A'),
    0x48: partial(decode_test_bit, 1, 'B'),
    0x49: partial(decode_test_bit, 1, 'C'),
    0x4a: partial(decode_test_bit, 1, 'D'),
    0x4b: partial(decode_test_bit, 1, 'E'),
    0x4c: partial(decode_test_bit, 1, 'H'),
    0x4d: partial(decode_test_bit, 1, 'L'),
    0x4e: partial(decode_test_bit, 1, '(HL)'),
    0x4f: partial(decode_test_bit, 1, 'A'),
    0x50: partial(decode_test_bit, 2, 'B'),
    0x51: partial(decode_test_bit, 2, 'C'),
    0x52: partial(decode_test_bit, 2, 'D'),
    0x53: partial(decode_test_bit, 2, 'E'),
    0x54: partial(decode_test_bit, 2, 'H'),
    0x55: partial(decode_test_bit, 2, 'L'),
    0x56: partial(decode_test_bit, 2, '(HL)'),
    0x57: partial(decode_test_bit, 2, 'A'),
    0x58: partial(decode_test_bit, 3, 'B'),
    0x59: partial(decode_test_bit, 3, 'C'),
    0x5a: partial(decode_test_bit, 3, 'D'),
    0x5b: partial(decode_test_bit, 3, 'E'),
    0x5c: partial(decode_test_bit, 3, 'H'),
    0x5d: partial(decode_test_bit, 3, 'L'),
    0x5e: partial(decode_test_bit, 3, '(HL)'),
    0x5f: partial(decode_test_bit, 3, 'A'),
    0x60: partial(decode_test_bit, 4, 'B'),
    0x61: partial(decode_test_bit, 4, 'C'),
    0x62: partial(decode_test_bit, 4, 'D'),
    0x63: partial(decode_test_bit, 4, 'E'),
    0x64: partial(decode_test_bit, 4, 'H'),
    0x65: partial(decode_test_bit, 4, 'L'),
    0x66: partial(decode_test_bit, 4, '(HL)'),
    0x67: partial(decode_test_bit, 4, 'A'),
    0x68: partial(decode_test_bit, 5, 'B'),
    0x69: partial(decode_test_bit, 5, 'C'),
    0x6a: partial(decode_test_bit, 5, 'D'),
    0x6b: partial(decode_test_bit, 5, 'E'),
    0x6c: partial(decode_test_bit, 5, 'H'),
    0x6d: partial(decode_test_bit, 5, 'L'),
    0x6e: partial(decode_test_bit, 5, '(HL)'),
    0x6f: partial(decode_test_bit, 5, 'A'),
    0x70: partial(decode_test_bit, 6, 'B'),
    0x71: partial(decode_test_bit, 6, 'C'),
    0x72: partial(decode_test_bit, 6, 'D'),
    0x73: partial(decode_test_bit, 6, 'E'),
    0x74: partial(decode_test_bit, 6, 'H'),
    0x75: partial(decode_test_bit, 6, 'L'),
    0x76: partial(decode_test_bit, 6, '(HL)'),
    0x77: partial(decode_test_bit, 6, 'A'),
    0x78: partial(decode_test_bit, 7, 'B'),
    0x79: partial(decode_test_bit, 7, 'C'),
    0x7a: partial(decode_test_bit, 7, 'D'),
    0x7b: partial(decode_test_bit, 7, 'E'),
    0x7c: partial(decode_test_bit, 7, 'H'),
    0x7d: partial(decode_test_bit, 7, 'L'),
    0x7e: partial(decode_test_bit, 7, '(HL)'),
    0x7f: partial(decode_test_bit, 7, 'A'),
    0x80: partial(decode_reset_bit, 0, 'B'),
    0x81: partial(decode_reset_bit, 0, 'C'),
    0x82: partial(decode_reset_bit, 0, 'D'),
    0x83: partial(decode_reset_bit, 0, 'E'),
    0x84: partial(decode_reset_bit, 0, 'H'),
    0x85: partial(decode_reset_bit, 0, 'L'),
    0x86: partial(decode_reset_bit, 0, '(HL)'),
    0x87: partial(decode_reset_bit, 0, 'A'),
    0x88: partial(decode_reset_bit, 1, 'B'),
    0x89: partial(decode_reset_bit, 1, 'C'),
    0x8a: partial(decode_reset_bit, 1, 'D'),
    0x8b: partial(decode_reset_bit, 1, 'E'),
    0x8c: partial(decode_reset_bit, 1, 'H'),
    0x8d: partial(decode_reset_bit, 1, 'L'),
    0x8e: partial(decode_reset_bit, 1, '(HL)'),
    0x8f: partial(decode_reset_bit, 1, 'A'),
    0x90: partial(decode_reset_bit, 2, 'B'),
    0x91: partial(decode_reset_bit, 2, 'C'),
    0x92: partial(decode_reset_bit, 2, 'D'),
    0x93: partial(decode_reset_bit, 2, 'E'),
    0x94: partial(decode_reset_bit, 2, 'H'),
    0x95: partial(decode_reset_bit, 2, 'L'),
    0x96: partial(decode_reset_bit, 2, '(HL)'),
    0x97: partial(decode_reset_bit, 2, 'A'),
    0x98: partial(decode_reset_bit, 3, 'B'),
    0x99: partial(decode_reset_bit, 3, 'C'),
    0x9a: partial(decode_reset_bit, 3, 'D'),
    0x9b: partial(decode_reset_bit, 3, 'E'),
    0x9c: partial(decode_reset_bit, 3, 'H'),
    0x9d: partial(decode_reset_bit, 3, 'L'),
    0x9e: partial(decode_reset_bit, 3, '(HL)'),
    0x9f: partial(decode_reset_bit, 3, 'A'),
    0xa0: partial(decode_reset_bit, 4, 'B'),
    0xa1: partial(decode_reset_bit, 4, 'C'),
    0xa2: partial(decode_reset_bit, 4, 'D'),
    0xa3: partial(decode_reset_bit, 4, 'E'),
    0xa4: partial(decode_reset_bit, 4, 'H'),
    0xa5: partial(decode_reset_bit, 4, 'L'),
    0xa6: partial(decode_reset_bit, 4, '(HL)'),
    0xa7: partial(decode_reset_bit, 4, 'A'),
    0xa8: partial(decode_reset_bit, 5, 'B'),
    0xa9: partial(decode_reset_bit, 5, 'C'),
    0xaa: partial(decode_reset_bit, 5, 'D'),
    0xab: partial(decode_reset_bit, 5, 'E'),
    0xac: partial(decode_reset_bit, 5, 'H'),
    0xad: partial(decode_reset_bit, 5, 'L'),
    0xae: partial(decode_reset_bit, 5, '(HL)'),
    0xaf: partial(decode_reset_bit, 5, 'A'),
    0xb0: partial(decode_reset_bit, 6, 'B'),
    0xb1: partial(decode_reset_bit, 6, 'C'),
    0xb2: partial(decode_reset_bit, 6, 'D'),
    0xb3: partial(decode_reset_bit, 6, 'E'),
    0xb4: partial(decode_reset_bit, 6, 'H'),
    0xb5: partial(decode_reset_bit, 6, 'L'),
    0xb6: partial(decode_reset_bit, 6, '(HL)'),
    0xb7: partial(decode_reset_bit, 6, 'A'),
    0xb8: partial(decode_reset_bit, 7, 'B'),
    0xb9: partial(decode_reset_bit, 7, 'C'),
    0xba: partial(decode_reset_bit, 7, 'D'),
    0xbb: partial(decode_reset_bit, 7, 'E'),
    0xbc: partial(decode_reset_bit, 7, 'H'),
    0xbd: partial(decode_reset_bit, 7, 'L'),
    0xbe: partial(decode_reset_bit, 7, '(HL)'),
    0xbf: partial(decode_reset_bit, 7, 'A'),
    0xc0: partial(decode_set_bit, 0, 'B'),
    0xc1: partial(decode_set_bit, 0, 'C'),
    0xc2: partial(decode_set_bit, 0, 'D'),
    0xc3: partial(decode_set_bit, 0, 'E'),
    0xc4: partial(decode_set_bit, 0, 'H'),
    0xc5: partial(decode_set_bit, 0, 'L'),
    0xc6: partial(decode_set_bit, 0, '(HL)'),
    0xc7: partial(decode_set_bit, 0, 'A'),
    0xc8: partial(decode_set_bit, 1, 'B'),
    0xc9: partial(decode_set_bit, 1, 'C'),
    0xca: partial(decode_set_bit, 1, 'D'),
    0xcb: partial(decode_set_bit, 1, 'E'),
    0xcc: partial(decode_set_bit, 1, 'H'),
    0xcd: partial(decode_set_bit, 1, 'L'),
    0xce: partial(decode_set_bit, 1, '(HL)'),
    0xcf: partial(decode_set_bit, 1, 'A'),
    0xd0: partial(decode_set_bit, 2, 'B'),
    0xd1: partial(decode_set_bit, 2, 'C'),
    0xd2: partial(decode_set_bit, 2, 'D'),
    0xd3: partial(decode_set_bit, 2, 'E'),
    0xd4: partial(decode_set_bit, 2, 'H'),
    0xd5: partial(decode_set_bit, 2, 'L'),
    0xd6: partial(decode_set_bit, 2, '(HL)'),
    0xd7: partial(decode_set_bit, 2, 'A'),
    0xd8: partial(decode_set_bit, 3, 'B'),
    0xd9: partial(decode_set_bit, 3, 'C'),
    0xda: partial(decode_set_bit, 3, 'D'),
    0xdb: partial(decode_set_bit, 3, 'E'),
    0xdc: partial(decode_set_bit, 3, 'H'),
    0xdd: partial(decode_set_bit, 3, 'L'),
    0xde: partial(decode_set_bit, 3, '(HL)'),
    0xdf: partial(decode_set_bit, 3, 'A'),
    0xe0: partial(decode_set_bit, 4, 'B'),
    0xe1: partial(decode_set_bit, 4, 'C'),
    0xe2: partial(decode_set_bit, 4, 'D'),
    0xe3: partial(decode_set_bit, 4, 'E'),
    0xe4: partial(decode_set_bit, 4, 'H'),
    0xe5: partial(decode_set_bit, 4, 'L'),
    0xe6: partial(decode_set_bit, 4, '(HL)'),
    0xe7: partial(decode_set_bit, 4, 'A'),
    0xe8: partial(decode_set_bit, 5, 'B'),
    0xe9: partial(decode_set_bit, 5, 'C'),
    0xea: partial(decode_set_bit, 5, 'D'),
    0xeb: partial(decode_set_bit, 5, 'E'),
    0xec: partial(decode_set_bit, 5, 'H'),
    0xed: partial(decode_set_bit, 5, 'L'),
    0xee: partial(decode_set_bit, 5, '(HL)'),
    0xef: partial(decode_set_bit, 5, 'A'),
    0xf0: partial(decode_set_bit, 6, 'B'),
    0xf1: partial(decode_set_bit, 6, 'C'),
    0xf2: partial(decode_set_bit, 6, 'D'),
    0xf3: partial(decode_set_bit, 6, 'E'),
    0xf4: partial(decode_set_bit, 6, 'H'),
    0xf5: partial(decode_set_bit, 6, 'L'),
    0xf6: partial(decode_set_bit, 6, '(HL)'),
    0xf7: partial(decode_set_bit, 6, 'A'),
    0xf8: partial(decode_set_bit, 7, 'B'),
    0xf9: partial(decode_set_bit, 7, 'C'),
    0xfa: partial(decode_set_bit, 7, 'D'),
    0xfb: partial(decode_set_bit, 7, 'E'),
    0xfc: partial(decode_set_bit, 7, 'H'),
    0xfd: partial(decode_set_bit, 7, 'L'),
    0xfe: partial(decode_set_bit, 7, '(HL)'),
    0xff: partial(decode_set_bit, 7, 'A'),
}

def decode_cbprefixed(data, addr, il: LowLevelILFunction):
    opcode = data[1]
    
    if opcode not in handlers_by_opcode_cbprefixed:
        return None
    return handlers_by_opcode_cbprefixed[opcode](data, addr, il)

handlers_by_opcode = {
    0x00: decode_nop,
    0x1: partial(decode_set_reg_d16, 'BC'),
    0x2: partial(decode_set_reg16_pointer_reg8, 'BC', 'A'),
    0x3: partial(decode_arithmetic_logical_reg16, 'BC', 'BC', ArithmeticLogicalOpcode.INC),
    0x4: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.INC),
    0x5: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.DEC),
    0x6: partial(decode_set_reg_d8, 'B'),
    0x7: decode_rlca,
    0x8: decode_set_a16_sp,
    0x9: partial(decode_arithmetic_logical_reg16, 'HL', 'BC', ArithmeticLogicalOpcode.ADD),
    0xa: partial(decode_set_reg8_reg16_pointer, 'A', 'BC'),
    0xb: partial(decode_arithmetic_logical_reg16, 'BC', 'BC', ArithmeticLogicalOpcode.DEC),
    0xc: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.INC),
    0xd: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.DEC),
    0xe: partial(decode_set_reg_d8, 'C'),
    0xf: decode_rrca,
    0x10: partial(decode_unimplemented, 2), # STOP
    0x11: partial(decode_set_reg_d16, 'DE'),
    0x12: partial(decode_set_reg16_pointer_reg8, 'DE', 'A'),
    0x13: partial(decode_arithmetic_logical_reg16, 'DE', 'DE', ArithmeticLogicalOpcode.INC),
    0x14: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.INC),
    0x15: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.DEC),
    0x16: partial(decode_set_reg_d8, 'D'),
    0x17: decode_rla,
    0x18: decode_jr_unconditional_r8,
    0x19: partial(decode_arithmetic_logical_reg16, 'HL', 'DE', ArithmeticLogicalOpcode.ADD),
    0x1a: partial(decode_set_reg8_reg16_pointer, 'A', 'DE'),
    0x1b: partial(decode_arithmetic_logical_reg16, 'DE', 'DE', ArithmeticLogicalOpcode.DEC),
    0x1c: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.INC),
    0x1d: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.DEC),
    0x1e: partial(decode_set_reg_d8, 'E'),
    0x1f: decode_rra,
    0x20: decode_jr_conditional_r8,
    0x21: partial(decode_set_reg_d16, 'HL'),
    0x22: partial(decode_set_reg16_pointer_reg8, 'HL+', 'A'),
    0x23: partial(decode_arithmetic_logical_reg16, 'HL', 'HL', ArithmeticLogicalOpcode.INC),
    0x24: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.INC),
    0x25: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.DEC),
    0x26: partial(decode_set_reg_d8, 'H'),
    0x27: partial(decode_unimplemented, 1), # DAA, this isn't done in Z80 either...
    0x28: decode_jr_conditional_r8,
    0x29: partial(decode_arithmetic_logical_reg16, 'HL', 'HL', ArithmeticLogicalOpcode.ADD),
    0x2a: partial(decode_set_reg8_reg16_pointer, 'A', 'HL+'),
    0x2b: partial(decode_arithmetic_logical_reg16, 'HL', 'HL', ArithmeticLogicalOpcode.DEC),
    0x2c: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.INC),
    0x2d: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.DEC),
    0x2e: partial(decode_set_reg_d8, 'L'),
    0x2f: decode_cpl,
    0x30: decode_jr_conditional_r8,
    0x31: partial(decode_set_reg_d16, 'SP'),
    0x32: partial(decode_set_reg16_pointer_reg8, 'HL+', 'A'),
    0x33: partial(decode_arithmetic_logical_reg16, 'SP', 'SP', ArithmeticLogicalOpcode.INC),
    0x34: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.INC),
    0x35: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.DEC),
    0x36: decode_set_hl_pointer_d8,
    0x37: decode_scf,
    0x38: decode_jr_conditional_r8,
    0x39: partial(decode_arithmetic_logical_reg16, 'HL', 'SP', ArithmeticLogicalOpcode.ADD),
    0x3a: partial(decode_set_reg8_reg16_pointer, 'A', 'HL-'),
    0x3b: partial(decode_arithmetic_logical_reg16, 'SP', 'SP', ArithmeticLogicalOpcode.DEC),
    0x3c: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.INC),
    0x3d: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.DEC),
    0x3e: partial(decode_set_reg_d8, 'A'),
    0x3f: decode_ccf,
    0x40: partial(decode_set_reg_reg8, 'B', 'B'),
    0x41: partial(decode_set_reg_reg8, 'B', 'C'),
    0x42: partial(decode_set_reg_reg8, 'B', 'D'),
    0x43: partial(decode_set_reg_reg8, 'B', 'E'),
    0x44: partial(decode_set_reg_reg8, 'B', 'H'),
    0x45: partial(decode_set_reg_reg8, 'B', 'L'),
    0x46: partial(decode_set_reg_reg8, 'B', '(HL)'),
    0x47: partial(decode_set_reg_reg8, 'B', 'A'),
    0x48: partial(decode_set_reg_reg8, 'C', 'B'),
    0x49: partial(decode_set_reg_reg8, 'C', 'C'),
    0x4a: partial(decode_set_reg_reg8, 'C', 'D'),
    0x4b: partial(decode_set_reg_reg8, 'C', 'E'),
    0x4c: partial(decode_set_reg_reg8, 'C', 'H'),
    0x4d: partial(decode_set_reg_reg8, 'C', 'L'),
    0x4e: partial(decode_set_reg_reg8, 'C', '(HL)'),
    0x4f: partial(decode_set_reg_reg8, 'C', 'A'),
    0x50: partial(decode_set_reg_reg8, 'D', 'B'),
    0x51: partial(decode_set_reg_reg8, 'D', 'C'),
    0x52: partial(decode_set_reg_reg8, 'D', 'D'),
    0x53: partial(decode_set_reg_reg8, 'D', 'E'),
    0x54: partial(decode_set_reg_reg8, 'D', 'H'),
    0x55: partial(decode_set_reg_reg8, 'D', 'L'),
    0x56: partial(decode_set_reg_reg8, 'D', '(HL)'),
    0x57: partial(decode_set_reg_reg8, 'D', 'A'),
    0x58: partial(decode_set_reg_reg8, 'E', 'B'),
    0x59: partial(decode_set_reg_reg8, 'E', 'C'),
    0x5a: partial(decode_set_reg_reg8, 'E', 'D'),
    0x5b: partial(decode_set_reg_reg8, 'E', 'E'),
    0x5c: partial(decode_set_reg_reg8, 'E', 'H'),
    0x5d: partial(decode_set_reg_reg8, 'E', 'L'),
    0x5e: partial(decode_set_reg_reg8, 'E', '(HL)'),
    0x5f: partial(decode_set_reg_reg8, 'E', 'A'),
    0x60: partial(decode_set_reg_reg8, 'H', 'B'),
    0x61: partial(decode_set_reg_reg8, 'H', 'C'),
    0x62: partial(decode_set_reg_reg8, 'H', 'D'),
    0x63: partial(decode_set_reg_reg8, 'H', 'E'),
    0x64: partial(decode_set_reg_reg8, 'H', 'H'),
    0x65: partial(decode_set_reg_reg8, 'H', 'L'),
    0x66: partial(decode_set_reg_reg8, 'H', '(HL)'),
    0x67: partial(decode_set_reg_reg8, 'H', 'A'),
    0x68: partial(decode_set_reg_reg8, 'L', 'B'),
    0x69: partial(decode_set_reg_reg8, 'L', 'C'),
    0x6a: partial(decode_set_reg_reg8, 'L', 'D'),
    0x6b: partial(decode_set_reg_reg8, 'L', 'E'),
    0x6c: partial(decode_set_reg_reg8, 'L', 'H'),
    0x6d: partial(decode_set_reg_reg8, 'L', 'L'),
    0x6e: partial(decode_set_reg_reg8, 'L', '(HL)'),
    0x6f: partial(decode_set_reg_reg8, 'L', 'A'),
    0x70: partial(decode_set_reg16_pointer_reg8, 'HL', 'B'),
    0x71: partial(decode_set_reg16_pointer_reg8, 'HL', 'C'),
    0x72: partial(decode_set_reg16_pointer_reg8, 'HL', 'D'),
    0x73: partial(decode_set_reg16_pointer_reg8, 'HL', 'E'),
    0x74: partial(decode_set_reg16_pointer_reg8, 'HL', 'H'),
    0x75: partial(decode_set_reg16_pointer_reg8, 'HL', 'L'),
    0x76: partial(decode_unimplemented, 1), # HALT
    0x77: partial(decode_set_reg16_pointer_reg8, 'HL', 'A'),
    0x78: partial(decode_set_reg_reg8, 'A', 'B'),
    0x79: partial(decode_set_reg_reg8, 'A', 'C'),
    0x7a: partial(decode_set_reg_reg8, 'A', 'D'),
    0x7b: partial(decode_set_reg_reg8, 'A', 'E'),
    0x7c: partial(decode_set_reg_reg8, 'A', 'H'),
    0x7d: partial(decode_set_reg_reg8, 'A', 'L'),
    0x7e: partial(decode_set_reg_reg8, 'A', '(HL)'),
    0x7f: partial(decode_set_reg_reg8, 'A', 'A'),
    0x80: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.ADD),
    0x81: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.ADD),
    0x82: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.ADD),
    0x83: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.ADD),
    0x84: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.ADD),
    0x85: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.ADD),
    0x86: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.ADD),
    0x87: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.ADD),
    0x88: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.ADC),
    0x89: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.ADC),
    0x8a: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.ADC),
    0x8b: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.ADC),
    0x8c: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.ADC),
    0x8d: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.ADC),
    0x8e: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.ADC),
    0x8f: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.ADC),
    0x90: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.SUB),
    0x91: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.SUB),
    0x92: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.SUB),
    0x93: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.SUB),
    0x94: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.SUB),
    0x95: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.SUB),
    0x96: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.SUB),
    0x97: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.SUB),
    0x98: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.SBC),
    0x99: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.SBC),
    0x9a: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.SBC),
    0x9b: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.SBC),
    0x9c: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.SBC),
    0x9d: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.SBC),
    0x9e: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.SBC),
    0x9f: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.SBC),
    0xa0: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.AND),
    0xa1: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.AND),
    0xa2: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.AND),
    0xa3: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.AND),
    0xa4: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.AND),
    0xa5: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.AND),
    0xa6: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.AND),
    0xa7: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.AND),
    0xa8: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.XOR),
    0xa9: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.XOR),
    0xaa: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.XOR),
    0xab: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.XOR),
    0xac: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.XOR),
    0xad: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.XOR),
    0xae: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.XOR),
    0xaf: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.XOR),
    0xb0: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.OR),
    0xb1: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.OR),
    0xb2: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.OR),
    0xb3: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.OR),
    0xb4: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.OR),
    0xb5: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.OR),
    0xb6: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.OR),
    0xb7: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.OR),
    0xb8: partial(decode_arithmetic_logical_8bit, 'B', ArithmeticLogicalOpcode.CMP),
    0xb9: partial(decode_arithmetic_logical_8bit, 'C', ArithmeticLogicalOpcode.CMP),
    0xba: partial(decode_arithmetic_logical_8bit, 'D', ArithmeticLogicalOpcode.CMP),
    0xbb: partial(decode_arithmetic_logical_8bit, 'E', ArithmeticLogicalOpcode.CMP),
    0xbc: partial(decode_arithmetic_logical_8bit, 'H', ArithmeticLogicalOpcode.CMP),
    0xbd: partial(decode_arithmetic_logical_8bit, 'L', ArithmeticLogicalOpcode.CMP),
    0xbe: partial(decode_arithmetic_logical_8bit, '(HL)', ArithmeticLogicalOpcode.CMP),
    0xbf: partial(decode_arithmetic_logical_8bit, 'A', ArithmeticLogicalOpcode.CMP),
    0xc0: decode_ret_conditional,
    0xc1: partial(decode_pop_reg16, 'BC'),
    0xc2: decode_jp_conditional_a16,
    0xc3: decode_jp_unconditional_a16,
    0xc4: decode_call_conditional_a16,
    0xc5: partial(decode_push_reg16, 'BC'),
    0xc6: partial(decode_arithmetic_logical_8bit, 'd8', ArithmeticLogicalOpcode.ADD),
    0xc7: partial(decode_rst, 0x00),
    0xc8: decode_ret_conditional,
    0xc9: decode_ret_unconditional,
    0xca: decode_jp_conditional_a16,
    0xcb: decode_cbprefixed,
    0xcc: decode_call_conditional_a16,
    0xcd: decode_call_unconditional_a16,
    0xce: partial(decode_arithmetic_logical_8bit, 'd8', ArithmeticLogicalOpcode.ADC),
    0xcf: partial(decode_rst, 0x08),
    0xd0: decode_ret_conditional,
    0xd1: partial(decode_pop_reg16, 'DE'),
    0xd2: decode_jp_conditional_a16,
    0xd4: decode_call_conditional_a16,
    0xd5: partial(decode_push_reg16, 'DE'),
    0xd6: partial(decode_arithmetic_logical_8bit, 'd8', ArithmeticLogicalOpcode.SUB),
    0xd7: partial(decode_rst, 0x10),
    0xd8: decode_ret_conditional,
    0xd9: decode_ret_unconditional,
    0xda: decode_jp_conditional_a16,
    0xdc: decode_call_conditional_a16,
    0xde: partial(decode_arithmetic_logical_8bit, 'd8', ArithmeticLogicalOpcode.SBC),
    0xdf: partial(decode_rst, 0x18),
    0xe0: decode_set_a8_a,
    0xe1: partial(decode_pop_reg16, 'HL'),
    0xe2: decode_set_c_a,
    0xe5: partial(decode_push_reg16, 'HL'),
    0xe6: partial(decode_arithmetic_logical_8bit, 'd8', ArithmeticLogicalOpcode.AND),
    0xe7: partial(decode_rst, 0x20),
    0xe8: decode_add_sp_r8,
    0xe9: decode_jp_hl,
    0xea: decode_set_a16_a,
    0xee: partial(decode_arithmetic_logical_8bit, 'd8', ArithmeticLogicalOpcode.XOR),
    0xef: partial(decode_rst, 0x2f),
    0xf0: decode_set_a_a8,
    0xf1: decode_pop_af,
    0xf2: decode_set_a_c,
    0xf3: partial(decode_unimplemented, 1), # DI
    0xf5: decode_push_af,
    0xf6: partial(decode_arithmetic_logical_8bit, 'd8', ArithmeticLogicalOpcode.OR),
    0xf7: partial(decode_rst, 0x30),
    0xf8: decode_set_hl_sp_plus_d8,
    0xf9: decode_set_sp_hl,
    0xfa: decode_set_a_a16,
    0xfb: partial(decode_unimplemented, 1), # EI
    0xfe: decode_cp_d8,
    0xff: partial(decode_rst, 0x3f),
}

def lift_il(data, addr, il):
    opcode = data[0]

    if opcode not in handlers_by_opcode:
        return None
    
    return handlers_by_opcode[opcode](data, addr, il)

# thanks Z80 plugin https://github.com/Vector35/Z80/
def expressionify(size, foo, il, temps_are_conds=False):
    """ turns the "reg or constant"  operands to get_flag_write_low_level_il()
        into lifted expressions """
    if isinstance(foo, ILRegister):
        # LowLevelILExpr is different than ILRegister
        if temps_are_conds and LLIL_TEMP(foo.index):
            # can't use il.reg() 'cause it will do lookup in architecture flags
            return il.expr(LowLevelILOperation.LLIL_FLAG, foo.index)
            #return il.reg(size, 'cond:%d' % LLIL_GET_TEMP_REG_INDEX(foo))

        # promote it to an LLIL_REG (read register)
        return il.reg(size, foo)

    elif isinstance(foo, ILFlag):
        return il.flag(foo)

    elif isinstance(foo, int):
        return il.const(size, foo)

    else:
        raise Exception('expressionify() doesn\'t know how to handle il: %s\n%s\n' % (foo, type(foo)))

def lift_flag_il(op, size, write_type, flag, operands, il):
    if flag == 'z':
        if op == LowLevelILOperation.LLIL_AND:
            return il.compare_equal(size,
                il.and_expr(size,
                    expressionify(size, operands[0], il),
                    expressionify(size, operands[1], il),
                ),
                il.const(1, 0)
            )
        elif op == LowLevelILOperation.LLIL_XOR:
            return il.compare_equal(size,
                il.and_expr(size,
                    expressionify(size, operands[0], il),
                    expressionify(size, operands[1], il),
                ),
                il.const(1, 0)
            )
        elif op == LowLevelILOperation.LLIL_OR:
            return il.compare_equal(size,
                il.or_expr(size,
                    expressionify(size, operands[0], il),
                    expressionify(size, operands[1], il),
                ),
                il.const(1, 0)
            )
    
    if flag == 'n':
        if op == LowLevelILOperation.LLIL_AND:
            return il.const(1, 0)
        elif op == LowLevelILOperation.LLIL_XOR:
            return il.const(1, 0)
        elif op == LowLevelILOperation.LLIL_OR:
            return il.const(1, 0)
        elif op == LowLevelILOperation.LLIL_ADD:
            return il.const(1, 0)
        elif op == LowLevelILOperation.LLIL_ADC:
            return il.const(1, 0)
        elif op == LowLevelILOperation.LLIL_SUB:
            return il.const(1, 1)
        elif op == LowLevelILOperation.LLIL_SBB:
            return il.const(1, 1)
        
    if flag == 'h':
        if op == LowLevelILOperation.LLIL_AND:
            return il.const(1, 1)
        elif op == LowLevelILOperation.LLIL_XOR:
            return il.const(1, 0)
        elif op == LowLevelILOperation.LLIL_OR:
            return il.const(1, 0)
        # these are yuck and only matter if we get DAA working
        elif op == LowLevelILOperation.LLIL_SUB:
            # only use bottom 4 bits of registers
            lhs = il.and_expr(size, il.const(size, 0x0F), expressionify(size, operands[0], il))
            rhs = il.and_expr(size, il.const(size, 0x0F), expressionify(size, operands[1], il))
            # perform operation
            half_operation = il.sub(size, lhs, rhs)
            # check bit 4
            return il.test_bit(size, half_operation, il.const(size, 1<<4))
        elif op == LowLevelILOperation.LLIL_ADD:
            # only use bottom 4 bits of registers
            lhs = il.and_expr(size, il.const(size, 0x0F), expressionify(size, operands[0], il))
            rhs = il.and_expr(size, il.const(size, 0x0F), expressionify(size, operands[1], il))
            # perform operation
            half_operation = il.add(size, lhs, rhs)
            # check bit 4
            return il.test_bit(size, half_operation, il.const(size, 1<<4))
        elif op == LowLevelILOperation.LLIL_ADC:
            # only use bottom 4 bits of registers
            lhs = il.and_expr(size, il.const(size, 0x0F), expressionify(size, operands[0], il))
            rhs = il.and_expr(size, il.const(size, 0x0F), expressionify(size, operands[1], il))
            # perform operation
            half_operation = il.add_carry(size, lhs, rhs, il.flag("c"))
            # check bit 4
            return il.test_bit(size, half_operation, il.const(size, 1<<4))
        elif op == LowLevelILOperation.LLIL_SBB:
            # only use bottom 4 bits of registers
            lhs = il.and_expr(size, il.const(size, 0x0F), expressionify(size, operands[0], il))
            rhs = il.and_expr(size, il.const(size, 0x0F), expressionify(size, operands[1], il))
            # perform operation
            half_operation = il.sub_borrow(size, lhs, rhs, il.flag("c"))
            # check bit 4
            return il.test_bit(size, half_operation, il.const(size, 1<<4))

        
    if flag == 'c':
        if op == LowLevelILOperation.LLIL_AND:
            return il.const(1, 0)
        elif op == LowLevelILOperation.LLIL_XOR:
            return il.const(1, 0)
        elif op == LowLevelILOperation.LLIL_OR:
            return il.const(1, 0)
        # others are done but not this one for some reason
        # rest is standard carry flag stuff
        elif op == LowLevelILOperation.LLIL_SBB:
            lhs = expressionify(size, operands[0], il)
            rhs = expressionify(size, operands[1], il)
            # perform operation
            operation = il.sub_borrow(size, lhs, rhs, il.flag("c"))
            # if we've overflowed then we'll be larger than when we started
            return il.compare_unsigned_greater_than(size, operation, lhs)
