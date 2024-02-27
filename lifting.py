import struct
from functools import partial
from binaryninja.enums import LowLevelILFlagCondition
from binaryninja.lowlevelil import LowLevelILLabel, LowLevelILFunction

from enum import Enum, auto

class ArithmeticLogicalOpcode(Enum):
    ADD = auto()
    ADC = auto()
    SUB = auto()
    SBC = auto()
    AND = auto()
    XOR = auto()
    OR = auto()
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

def decode_jp_unconditional_a16(data, addr, il: LowLevelILFunction):
    dest_address = struct.unpack("<H", data[1:3])[0]
    label = il.get_label_for_address(il.arch, dest_address)
    if label:
        il.append(il.goto(label))
    else:
        il.append(il.jump(il.const_pointer(2, dest_address)))
    return 3

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
    # if there are no flags to process here then assume the code is wrong
    if not cond:
        print("addr %X, cond = 0, opcode = %X" % (addr, opcode))
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
    # if there are no flags to process here then assume the code is wrong
    if not cond:
        print("addr %X, cond = 0, opcode = %X" % (addr, opcode))
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

def load_hl_pointer(il: LowLevelILFunction):
    return il.load(1, il.reg(2, 'HL'))

def store_hl_pointer(value, il: LowLevelILFunction):
    return il.store(1, il.reg(2, 'HL'), value)

def decode_cp(src, il: LowLevelILFunction):
    return il.sub(1, il.reg(1, 'A'), src, '*')

def decode_cp_reg(src_reg, data, addr, il: LowLevelILFunction):
    il.append(decode_cp(il.reg(1, src_reg), il))
    return 1

def decode_cp_hl_pointer(data, addr, il: LowLevelILFunction):
    il.append(decode_cp(load_hl_pointer(il), il))
    return 1

def decode_cp_d8(data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<B', data[1:2])[0]
    il.append(decode_cp(il.const(1, arg), il))
    return 2

def decode_arithmetic_logical_reg16(reg, opcode, data, addr, il: LowLevelILFunction):
    src_reg = il.reg(2, reg)
    if opcode == ArithmeticLogicalOpcode.INC:
        expression = il.add(2, src_reg, il.const(2, 1))
    elif opcode == ArithmeticLogicalOpcode.DEC:
        expression = il.sub(2, src_reg, il.const(2, 1))
    else:
        il.append(il.unimplemented())
        return 1
    
    il.append(il.set_reg(2, reg, expression))
    return 1

def decode_arithmetic_logical_reg8(reg, opcode, data, addr, il: LowLevelILFunction):
    src_reg = il.reg(1, reg)
    dest_reg = il.reg(1, 'A')
    if opcode == ArithmeticLogicalOpcode.XOR:
        expression = il.xor_expr(1, dest_reg, src_reg, '*')
    elif opcode == ArithmeticLogicalOpcode.OR:
        expression = il.or_expr(1, dest_reg, src_reg, '*')
    elif opcode == ArithmeticLogicalOpcode.INC:
        expression = il.add(1, src_reg, il.const(1, 1))
    elif opcode == ArithmeticLogicalOpcode.DEC:
        expression = il.sub(1, src_reg, il.const(1, 1))
    else:
        il.append(il.unimplemented())
        return 1
    
    if opcode == ArithmeticLogicalOpcode.INC or opcode == ArithmeticLogicalOpcode.DEC:
        il.append(il.set_reg(1, reg, expression))
    else:
        il.append(il.set_reg(1, 'A', expression))

    return 1

def decode_set_hl_pointer_d8(data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<B', data[1:2])[0]
    il.append(store_hl_pointer(il.const(1, arg), il))
    return 2

def decode_set_reg_d8(reg, data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<B', data[1:2])[0]
    il.append(il.set_reg(1, reg, il.const(1, arg)))
    return 2

def decode_set_reg_reg8(dest_reg, src_reg, data, addr, il: LowLevelILFunction):
    il.append(il.set_reg(1, dest_reg, il.reg(1, src_reg)))
    return 1

def decode_set_reg_d16(reg, data, addr, il: LowLevelILFunction):
    arg = struct.unpack('<H', data[1:3])[0]
    il.append(il.set_reg(2, reg, il.const(2, arg)))
    return 3

def decode_set_a16_a(data, addr, il: LowLevelILFunction):
    dest_address = struct.unpack('<H', data[1:3])[0]
    il.append(il.store(1, il.const_pointer(2, dest_address), il.reg(1, 'A')))
    return 3

def decode_store_a8_a(data, addr, il: LowLevelILFunction):
    dest_address = 0xFF00 + struct.unpack('<B', data[1:2])[0]
    il.append(il.store(1, il.const_pointer(2, dest_address), il.reg(1, 'A')))
    return 2
    

handlers_by_opcode_cbprefixed = {
    0x0: partial(decode_unimplemented, 2),
    0x1: partial(decode_unimplemented, 2),
    0x2: partial(decode_unimplemented, 2),
    0x3: partial(decode_unimplemented, 2),
    0x4: partial(decode_unimplemented, 2),
    0x5: partial(decode_unimplemented, 2),
    0x6: partial(decode_unimplemented, 2),
    0x7: partial(decode_unimplemented, 2),
    0x8: partial(decode_unimplemented, 2),
    0x9: partial(decode_unimplemented, 2),
    0xa: partial(decode_unimplemented, 2),
    0xb: partial(decode_unimplemented, 2),
    0xc: partial(decode_unimplemented, 2),
    0xd: partial(decode_unimplemented, 2),
    0xe: partial(decode_unimplemented, 2),
    0xf: partial(decode_unimplemented, 2),
    0x10: partial(decode_unimplemented, 2),
    0x11: partial(decode_unimplemented, 2),
    0x12: partial(decode_unimplemented, 2),
    0x13: partial(decode_unimplemented, 2),
    0x14: partial(decode_unimplemented, 2),
    0x15: partial(decode_unimplemented, 2),
    0x16: partial(decode_unimplemented, 2),
    0x17: partial(decode_unimplemented, 2),
    0x18: partial(decode_unimplemented, 2),
    0x19: partial(decode_unimplemented, 2),
    0x1a: partial(decode_unimplemented, 2),
    0x1b: partial(decode_unimplemented, 2),
    0x1c: partial(decode_unimplemented, 2),
    0x1d: partial(decode_unimplemented, 2),
    0x1e: partial(decode_unimplemented, 2),
    0x1f: partial(decode_unimplemented, 2),
    0x20: partial(decode_unimplemented, 2),
    0x21: partial(decode_unimplemented, 2),
    0x22: partial(decode_unimplemented, 2),
    0x23: partial(decode_unimplemented, 2),
    0x24: partial(decode_unimplemented, 2),
    0x25: partial(decode_unimplemented, 2),
    0x26: partial(decode_unimplemented, 2),
    0x27: partial(decode_unimplemented, 2),
    0x28: partial(decode_unimplemented, 2),
    0x29: partial(decode_unimplemented, 2),
    0x2a: partial(decode_unimplemented, 2),
    0x2b: partial(decode_unimplemented, 2),
    0x2c: partial(decode_unimplemented, 2),
    0x2d: partial(decode_unimplemented, 2),
    0x2e: partial(decode_unimplemented, 2),
    0x2f: partial(decode_unimplemented, 2),
    0x30: partial(decode_unimplemented, 2),
    0x31: partial(decode_unimplemented, 2),
    0x32: partial(decode_unimplemented, 2),
    0x33: partial(decode_unimplemented, 2),
    0x34: partial(decode_unimplemented, 2),
    0x35: partial(decode_unimplemented, 2),
    0x36: partial(decode_unimplemented, 2),
    0x37: partial(decode_unimplemented, 2),
    0x38: partial(decode_unimplemented, 2),
    0x39: partial(decode_unimplemented, 2),
    0x3a: partial(decode_unimplemented, 2),
    0x3b: partial(decode_unimplemented, 2),
    0x3c: partial(decode_unimplemented, 2),
    0x3d: partial(decode_unimplemented, 2),
    0x3e: partial(decode_unimplemented, 2),
    0x3f: partial(decode_unimplemented, 2),
    0x40: partial(decode_unimplemented, 2),
    0x41: partial(decode_unimplemented, 2),
    0x42: partial(decode_unimplemented, 2),
    0x43: partial(decode_unimplemented, 2),
    0x44: partial(decode_unimplemented, 2),
    0x45: partial(decode_unimplemented, 2),
    0x46: partial(decode_unimplemented, 2),
    0x47: partial(decode_unimplemented, 2),
    0x48: partial(decode_unimplemented, 2),
    0x49: partial(decode_unimplemented, 2),
    0x4a: partial(decode_unimplemented, 2),
    0x4b: partial(decode_unimplemented, 2),
    0x4c: partial(decode_unimplemented, 2),
    0x4d: partial(decode_unimplemented, 2),
    0x4e: partial(decode_unimplemented, 2),
    0x4f: partial(decode_unimplemented, 2),
    0x50: partial(decode_unimplemented, 2),
    0x51: partial(decode_unimplemented, 2),
    0x52: partial(decode_unimplemented, 2),
    0x53: partial(decode_unimplemented, 2),
    0x54: partial(decode_unimplemented, 2),
    0x55: partial(decode_unimplemented, 2),
    0x56: partial(decode_unimplemented, 2),
    0x57: partial(decode_unimplemented, 2),
    0x58: partial(decode_unimplemented, 2),
    0x59: partial(decode_unimplemented, 2),
    0x5a: partial(decode_unimplemented, 2),
    0x5b: partial(decode_unimplemented, 2),
    0x5c: partial(decode_unimplemented, 2),
    0x5d: partial(decode_unimplemented, 2),
    0x5e: partial(decode_unimplemented, 2),
    0x5f: partial(decode_unimplemented, 2),
    0x60: partial(decode_unimplemented, 2),
    0x61: partial(decode_unimplemented, 2),
    0x62: partial(decode_unimplemented, 2),
    0x63: partial(decode_unimplemented, 2),
    0x64: partial(decode_unimplemented, 2),
    0x65: partial(decode_unimplemented, 2),
    0x66: partial(decode_unimplemented, 2),
    0x67: partial(decode_unimplemented, 2),
    0x68: partial(decode_unimplemented, 2),
    0x69: partial(decode_unimplemented, 2),
    0x6a: partial(decode_unimplemented, 2),
    0x6b: partial(decode_unimplemented, 2),
    0x6c: partial(decode_unimplemented, 2),
    0x6d: partial(decode_unimplemented, 2),
    0x6e: partial(decode_unimplemented, 2),
    0x6f: partial(decode_unimplemented, 2),
    0x70: partial(decode_unimplemented, 2),
    0x71: partial(decode_unimplemented, 2),
    0x72: partial(decode_unimplemented, 2),
    0x73: partial(decode_unimplemented, 2),
    0x74: partial(decode_unimplemented, 2),
    0x75: partial(decode_unimplemented, 2),
    0x76: partial(decode_unimplemented, 2),
    0x77: partial(decode_unimplemented, 2),
    0x78: partial(decode_unimplemented, 2),
    0x79: partial(decode_unimplemented, 2),
    0x7a: partial(decode_unimplemented, 2),
    0x7b: partial(decode_unimplemented, 2),
    0x7c: partial(decode_unimplemented, 2),
    0x7d: partial(decode_unimplemented, 2),
    0x7e: partial(decode_unimplemented, 2),
    0x7f: partial(decode_unimplemented, 2),
    0x80: partial(decode_unimplemented, 2),
    0x81: partial(decode_unimplemented, 2),
    0x82: partial(decode_unimplemented, 2),
    0x83: partial(decode_unimplemented, 2),
    0x84: partial(decode_unimplemented, 2),
    0x85: partial(decode_unimplemented, 2),
    0x86: partial(decode_unimplemented, 2),
    0x87: partial(decode_unimplemented, 2),
    0x88: partial(decode_unimplemented, 2),
    0x89: partial(decode_unimplemented, 2),
    0x8a: partial(decode_unimplemented, 2),
    0x8b: partial(decode_unimplemented, 2),
    0x8c: partial(decode_unimplemented, 2),
    0x8d: partial(decode_unimplemented, 2),
    0x8e: partial(decode_unimplemented, 2),
    0x8f: partial(decode_unimplemented, 2),
    0x90: partial(decode_unimplemented, 2),
    0x91: partial(decode_unimplemented, 2),
    0x92: partial(decode_unimplemented, 2),
    0x93: partial(decode_unimplemented, 2),
    0x94: partial(decode_unimplemented, 2),
    0x95: partial(decode_unimplemented, 2),
    0x96: partial(decode_unimplemented, 2),
    0x97: partial(decode_unimplemented, 2),
    0x98: partial(decode_unimplemented, 2),
    0x99: partial(decode_unimplemented, 2),
    0x9a: partial(decode_unimplemented, 2),
    0x9b: partial(decode_unimplemented, 2),
    0x9c: partial(decode_unimplemented, 2),
    0x9d: partial(decode_unimplemented, 2),
    0x9e: partial(decode_unimplemented, 2),
    0x9f: partial(decode_unimplemented, 2),
    0xa0: partial(decode_unimplemented, 2),
    0xa1: partial(decode_unimplemented, 2),
    0xa2: partial(decode_unimplemented, 2),
    0xa3: partial(decode_unimplemented, 2),
    0xa4: partial(decode_unimplemented, 2),
    0xa5: partial(decode_unimplemented, 2),
    0xa6: partial(decode_unimplemented, 2),
    0xa7: partial(decode_unimplemented, 2),
    0xa8: partial(decode_unimplemented, 2),
    0xa9: partial(decode_unimplemented, 2),
    0xaa: partial(decode_unimplemented, 2),
    0xab: partial(decode_unimplemented, 2),
    0xac: partial(decode_unimplemented, 2),
    0xad: partial(decode_unimplemented, 2),
    0xae: partial(decode_unimplemented, 2),
    0xaf: partial(decode_unimplemented, 2),
    0xb0: partial(decode_unimplemented, 2),
    0xb1: partial(decode_unimplemented, 2),
    0xb2: partial(decode_unimplemented, 2),
    0xb3: partial(decode_unimplemented, 2),
    0xb4: partial(decode_unimplemented, 2),
    0xb5: partial(decode_unimplemented, 2),
    0xb6: partial(decode_unimplemented, 2),
    0xb7: partial(decode_unimplemented, 2),
    0xb8: partial(decode_unimplemented, 2),
    0xb9: partial(decode_unimplemented, 2),
    0xba: partial(decode_unimplemented, 2),
    0xbb: partial(decode_unimplemented, 2),
    0xbc: partial(decode_unimplemented, 2),
    0xbd: partial(decode_unimplemented, 2),
    0xbe: partial(decode_unimplemented, 2),
    0xbf: partial(decode_unimplemented, 2),
    0xc0: partial(decode_unimplemented, 2),
    0xc1: partial(decode_unimplemented, 2),
    0xc2: partial(decode_unimplemented, 2),
    0xc3: partial(decode_unimplemented, 2),
    0xc4: partial(decode_unimplemented, 2),
    0xc5: partial(decode_unimplemented, 2),
    0xc6: partial(decode_unimplemented, 2),
    0xc7: partial(decode_unimplemented, 2),
    0xc8: partial(decode_unimplemented, 2),
    0xc9: partial(decode_unimplemented, 2),
    0xca: partial(decode_unimplemented, 2),
    0xcb: partial(decode_unimplemented, 2),
    0xcc: partial(decode_unimplemented, 2),
    0xcd: partial(decode_unimplemented, 2),
    0xce: partial(decode_unimplemented, 2),
    0xcf: partial(decode_unimplemented, 2),
    0xd0: partial(decode_unimplemented, 2),
    0xd1: partial(decode_unimplemented, 2),
    0xd2: partial(decode_unimplemented, 2),
    0xd3: partial(decode_unimplemented, 2),
    0xd4: partial(decode_unimplemented, 2),
    0xd5: partial(decode_unimplemented, 2),
    0xd6: partial(decode_unimplemented, 2),
    0xd7: partial(decode_unimplemented, 2),
    0xd8: partial(decode_unimplemented, 2),
    0xd9: partial(decode_unimplemented, 2),
    0xda: partial(decode_unimplemented, 2),
    0xdb: partial(decode_unimplemented, 2),
    0xdc: partial(decode_unimplemented, 2),
    0xdd: partial(decode_unimplemented, 2),
    0xde: partial(decode_unimplemented, 2),
    0xdf: partial(decode_unimplemented, 2),
    0xe0: partial(decode_unimplemented, 2),
    0xe1: partial(decode_unimplemented, 2),
    0xe2: partial(decode_unimplemented, 2),
    0xe3: partial(decode_unimplemented, 2),
    0xe4: partial(decode_unimplemented, 2),
    0xe5: partial(decode_unimplemented, 2),
    0xe6: partial(decode_unimplemented, 2),
    0xe7: partial(decode_unimplemented, 2),
    0xe8: partial(decode_unimplemented, 2),
    0xe9: partial(decode_unimplemented, 2),
    0xea: partial(decode_unimplemented, 2),
    0xeb: partial(decode_unimplemented, 2),
    0xec: partial(decode_unimplemented, 2),
    0xed: partial(decode_unimplemented, 2),
    0xee: partial(decode_unimplemented, 2),
    0xef: partial(decode_unimplemented, 2),
    0xf0: partial(decode_unimplemented, 2),
    0xf1: partial(decode_unimplemented, 2),
    0xf2: partial(decode_unimplemented, 2),
    0xf3: partial(decode_unimplemented, 2),
    0xf4: partial(decode_unimplemented, 2),
    0xf5: partial(decode_unimplemented, 2),
    0xf6: partial(decode_unimplemented, 2),
    0xf7: partial(decode_unimplemented, 2),
    0xf8: partial(decode_unimplemented, 2),
    0xf9: partial(decode_unimplemented, 2),
    0xfa: partial(decode_unimplemented, 2),
    0xfb: partial(decode_unimplemented, 2),
    0xfc: partial(decode_unimplemented, 2),
    0xfd: partial(decode_unimplemented, 2),
    0xfe: partial(decode_unimplemented, 2),
    0xff: partial(decode_unimplemented, 2),
}

def decode_cbprefixed(data, addr, il: LowLevelILFunction):
    opcode = data[1]
    
    if opcode not in handlers_by_opcode_cbprefixed:
        return None
    return handlers_by_opcode_cbprefixed[opcode](data, addr, il)

handlers_by_opcode = {
    0x00: decode_nop,
    0x1: partial(decode_set_reg_d16, 'BC'),
    0x2: partial(decode_unimplemented, 1),
    0x3: partial(decode_arithmetic_logical_reg16, 'BC', ArithmeticLogicalOpcode.INC),
    0x4: partial(decode_arithmetic_logical_reg8, 'B', ArithmeticLogicalOpcode.INC),
    0x5: partial(decode_arithmetic_logical_reg8, 'B', ArithmeticLogicalOpcode.DEC),
    0x6: partial(decode_set_reg_d8, 'B'),
    0x7: partial(decode_unimplemented, 1),
    0x8: partial(decode_unimplemented, 3),
    0x9: partial(decode_unimplemented, 1),
    0xa: partial(decode_unimplemented, 1),
    0xb: partial(decode_arithmetic_logical_reg16, 'BC', ArithmeticLogicalOpcode.DEC),
    0xc: partial(decode_arithmetic_logical_reg8, 'C', ArithmeticLogicalOpcode.INC),
    0xd: partial(decode_arithmetic_logical_reg8, 'C', ArithmeticLogicalOpcode.DEC),
    0xe: partial(decode_set_reg_d8, 'C'),
    0xf: partial(decode_unimplemented, 1),
    0x10: partial(decode_unimplemented, 2),
    0x11: partial(decode_set_reg_d16, 'DE'),
    0x12: partial(decode_unimplemented, 1),
    0x13: partial(decode_arithmetic_logical_reg16, 'DE', ArithmeticLogicalOpcode.INC),
    0x14: partial(decode_arithmetic_logical_reg8, 'D', ArithmeticLogicalOpcode.INC),
    0x15: partial(decode_arithmetic_logical_reg8, 'D', ArithmeticLogicalOpcode.DEC),
    0x16: partial(decode_set_reg_d8, 'D'),
    0x17: partial(decode_unimplemented, 1),
    0x18: decode_jr_unconditional_r8,
    0x19: partial(decode_unimplemented, 1),
    0x1a: partial(decode_unimplemented, 1),
    0x1b: partial(decode_arithmetic_logical_reg16, 'DE', ArithmeticLogicalOpcode.DEC),
    0x1c: partial(decode_arithmetic_logical_reg8, 'E', ArithmeticLogicalOpcode.INC),
    0x1d: partial(decode_arithmetic_logical_reg8, 'E', ArithmeticLogicalOpcode.DEC),
    0x1e: partial(decode_set_reg_d8, 'E'),
    0x1f: partial(decode_unimplemented, 1),
    0x20: decode_jr_conditional_r8,
    0x21: partial(decode_set_reg_d16, 'HL'),
    0x22: partial(decode_unimplemented, 1),
    0x23: partial(decode_arithmetic_logical_reg16, 'HL', ArithmeticLogicalOpcode.INC),
    0x24: partial(decode_arithmetic_logical_reg8, 'H', ArithmeticLogicalOpcode.INC),
    0x25: partial(decode_arithmetic_logical_reg8, 'H', ArithmeticLogicalOpcode.DEC),
    0x26: partial(decode_set_reg_d8, 'H'),
    0x27: partial(decode_unimplemented, 1),
    0x28: decode_jr_conditional_r8,
    0x29: partial(decode_unimplemented, 1),
    0x2a: partial(decode_unimplemented, 1),
    0x2b: partial(decode_arithmetic_logical_reg16, 'HL', ArithmeticLogicalOpcode.DEC),
    0x2c: partial(decode_arithmetic_logical_reg8, 'L', ArithmeticLogicalOpcode.INC),
    0x2d: partial(decode_arithmetic_logical_reg8, 'L', ArithmeticLogicalOpcode.DEC),
    0x2e: partial(decode_set_reg_d8, 'L'),
    0x2f: partial(decode_unimplemented, 1),
    0x30: decode_jr_conditional_r8,
    0x31: partial(decode_set_reg_d16, 'SP'),
    0x32: partial(decode_unimplemented, 1),
    0x33: partial(decode_arithmetic_logical_reg16, 'SP', ArithmeticLogicalOpcode.INC),
    0x34: partial(decode_unimplemented, 1),
    0x35: partial(decode_unimplemented, 1),
    0x36: decode_set_hl_pointer_d8,
    0x37: partial(decode_unimplemented, 1),
    0x38: decode_jr_conditional_r8,
    0x39: partial(decode_unimplemented, 1),
    0x3a: partial(decode_unimplemented, 1),
    0x3b: partial(decode_arithmetic_logical_reg16, 'SP', ArithmeticLogicalOpcode.DEC),
    0x3c: partial(decode_arithmetic_logical_reg8, 'A', ArithmeticLogicalOpcode.INC),
    0x3d: partial(decode_arithmetic_logical_reg8, 'A', ArithmeticLogicalOpcode.DEC),
    0x3e: partial(decode_set_reg_d8, 'A'),
    0x3f: partial(decode_unimplemented, 1),
    0x40: partial(decode_set_reg_reg8, 'B', 'B'),
    0x41: partial(decode_set_reg_reg8, 'B', 'C'),
    0x42: partial(decode_set_reg_reg8, 'B', 'D'),
    0x43: partial(decode_set_reg_reg8, 'B', 'E'),
    0x44: partial(decode_set_reg_reg8, 'B', 'H'),
    0x45: partial(decode_set_reg_reg8, 'B', 'L'),
    0x46: partial(decode_unimplemented, 1),
    0x47: partial(decode_set_reg_reg8, 'B', 'A'),
    0x48: partial(decode_set_reg_reg8, 'C', 'B'),
    0x49: partial(decode_set_reg_reg8, 'C', 'C'),
    0x4a: partial(decode_set_reg_reg8, 'C', 'D'),
    0x4b: partial(decode_set_reg_reg8, 'C', 'E'),
    0x4c: partial(decode_set_reg_reg8, 'C', 'H'),
    0x4d: partial(decode_set_reg_reg8, 'C', 'L'),
    0x4e: partial(decode_unimplemented, 1),
    0x4f: partial(decode_set_reg_reg8, 'C', 'A'),
    0x50: partial(decode_set_reg_reg8, 'D', 'B'),
    0x51: partial(decode_set_reg_reg8, 'D', 'C'),
    0x52: partial(decode_set_reg_reg8, 'D', 'D'),
    0x53: partial(decode_set_reg_reg8, 'D', 'E'),
    0x54: partial(decode_set_reg_reg8, 'D', 'H'),
    0x55: partial(decode_set_reg_reg8, 'D', 'L'),
    0x56: partial(decode_unimplemented, 1),
    0x57: partial(decode_set_reg_reg8, 'D', 'A'),
    0x58: partial(decode_set_reg_reg8, 'E', 'B'),
    0x59: partial(decode_set_reg_reg8, 'E', 'C'),
    0x5a: partial(decode_set_reg_reg8, 'E', 'D'),
    0x5b: partial(decode_set_reg_reg8, 'E', 'E'),
    0x5c: partial(decode_set_reg_reg8, 'E', 'H'),
    0x5d: partial(decode_set_reg_reg8, 'E', 'L'),
    0x5e: partial(decode_unimplemented, 1),
    0x5f: partial(decode_set_reg_reg8, 'E', 'A'),
    0x60: partial(decode_set_reg_reg8, 'H', 'B'),
    0x61: partial(decode_set_reg_reg8, 'H', 'C'),
    0x62: partial(decode_set_reg_reg8, 'H', 'D'),
    0x63: partial(decode_set_reg_reg8, 'H', 'E'),
    0x64: partial(decode_set_reg_reg8, 'H', 'H'),
    0x65: partial(decode_set_reg_reg8, 'H', 'L'),
    0x66: partial(decode_unimplemented, 1),
    0x67: partial(decode_set_reg_reg8, 'H', 'A'),
    0x68: partial(decode_set_reg_reg8, 'L', 'B'),
    0x69: partial(decode_set_reg_reg8, 'L', 'C'),
    0x6a: partial(decode_set_reg_reg8, 'L', 'D'),
    0x6b: partial(decode_set_reg_reg8, 'L', 'E'),
    0x6c: partial(decode_set_reg_reg8, 'L', 'H'),
    0x6d: partial(decode_set_reg_reg8, 'L', 'L'),
    0x6e: partial(decode_unimplemented, 1),
    0x6f: partial(decode_set_reg_reg8, 'L', 'A'),
    0x70: partial(decode_unimplemented, 1),
    0x71: partial(decode_unimplemented, 1),
    0x72: partial(decode_unimplemented, 1),
    0x73: partial(decode_unimplemented, 1),
    0x74: partial(decode_unimplemented, 1),
    0x75: partial(decode_unimplemented, 1),
    0x76: partial(decode_unimplemented, 1),
    0x77: partial(decode_unimplemented, 1),
    0x78: partial(decode_set_reg_reg8, 'A', 'B'),
    0x79: partial(decode_set_reg_reg8, 'A', 'C'),
    0x7a: partial(decode_set_reg_reg8, 'A', 'D'),
    0x7b: partial(decode_set_reg_reg8, 'A', 'E'),
    0x7c: partial(decode_set_reg_reg8, 'A', 'H'),
    0x7d: partial(decode_set_reg_reg8, 'A', 'L'),
    0x7e: partial(decode_unimplemented, 1),
    0x7f: partial(decode_set_reg_reg8, 'A', 'A'),
    0x80: partial(decode_unimplemented, 1),
    0x81: partial(decode_unimplemented, 1),
    0x82: partial(decode_unimplemented, 1),
    0x83: partial(decode_unimplemented, 1),
    0x84: partial(decode_unimplemented, 1),
    0x85: partial(decode_unimplemented, 1),
    0x86: partial(decode_unimplemented, 1),
    0x87: partial(decode_unimplemented, 1),
    0x88: partial(decode_unimplemented, 1),
    0x89: partial(decode_unimplemented, 1),
    0x8a: partial(decode_unimplemented, 1),
    0x8b: partial(decode_unimplemented, 1),
    0x8c: partial(decode_unimplemented, 1),
    0x8d: partial(decode_unimplemented, 1),
    0x8e: partial(decode_unimplemented, 1),
    0x8f: partial(decode_unimplemented, 1),
    0x90: partial(decode_unimplemented, 1),
    0x91: partial(decode_unimplemented, 1),
    0x92: partial(decode_unimplemented, 1),
    0x93: partial(decode_unimplemented, 1),
    0x94: partial(decode_unimplemented, 1),
    0x95: partial(decode_unimplemented, 1),
    0x96: partial(decode_unimplemented, 1),
    0x97: partial(decode_unimplemented, 1),
    0x98: partial(decode_unimplemented, 1),
    0x99: partial(decode_unimplemented, 1),
    0x9a: partial(decode_unimplemented, 1),
    0x9b: partial(decode_unimplemented, 1),
    0x9c: partial(decode_unimplemented, 1),
    0x9d: partial(decode_unimplemented, 1),
    0x9e: partial(decode_unimplemented, 1),
    0x9f: partial(decode_unimplemented, 1),
    0xa0: partial(decode_unimplemented, 1),
    0xa1: partial(decode_unimplemented, 1),
    0xa2: partial(decode_unimplemented, 1),
    0xa3: partial(decode_unimplemented, 1),
    0xa4: partial(decode_unimplemented, 1),
    0xa5: partial(decode_unimplemented, 1),
    0xa6: partial(decode_unimplemented, 1),
    0xa7: partial(decode_unimplemented, 1),
    0xa8: partial(decode_arithmetic_logical_reg8, 'B', ArithmeticLogicalOpcode.XOR),
    0xa9: partial(decode_arithmetic_logical_reg8, 'C', ArithmeticLogicalOpcode.XOR),
    0xaa: partial(decode_arithmetic_logical_reg8, 'D', ArithmeticLogicalOpcode.XOR),
    0xab: partial(decode_arithmetic_logical_reg8, 'E', ArithmeticLogicalOpcode.XOR),
    0xac: partial(decode_arithmetic_logical_reg8, 'H', ArithmeticLogicalOpcode.XOR),
    0xad: partial(decode_arithmetic_logical_reg8, 'L', ArithmeticLogicalOpcode.XOR),
    0xae: partial(decode_unimplemented, 1),
    0xaf: partial(decode_arithmetic_logical_reg8, 'A', ArithmeticLogicalOpcode.XOR),
    0xb0: partial(decode_arithmetic_logical_reg8, 'B', ArithmeticLogicalOpcode.OR),
    0xb1: partial(decode_arithmetic_logical_reg8, 'C', ArithmeticLogicalOpcode.OR),
    0xb2: partial(decode_arithmetic_logical_reg8, 'D', ArithmeticLogicalOpcode.OR),
    0xb3: partial(decode_arithmetic_logical_reg8, 'E', ArithmeticLogicalOpcode.OR),
    0xb4: partial(decode_arithmetic_logical_reg8, 'H', ArithmeticLogicalOpcode.OR),
    0xb5: partial(decode_arithmetic_logical_reg8, 'L', ArithmeticLogicalOpcode.OR),
    0xb6: partial(decode_unimplemented, 1),
    0xb7: partial(decode_arithmetic_logical_reg8, 'A', ArithmeticLogicalOpcode.OR),
    0xb8: partial(decode_cp_reg, 'B'),
    0xb9: partial(decode_cp_reg, 'C'),
    0xba: partial(decode_cp_reg, 'D'),
    0xbb: partial(decode_cp_reg, 'E'),
    0xbc: partial(decode_cp_reg, 'H'),
    0xbd: partial(decode_cp_reg, 'L'),
    0xbe: decode_cp_hl_pointer,
    0xbf: partial(decode_cp_reg, 'A'),
    0xc0: partial(decode_unimplemented, 1),
    0xc1: partial(decode_unimplemented, 1),
    0xc2: partial(decode_unimplemented, 3),
    0xc3: decode_jp_unconditional_a16,
    0xc4: decode_call_conditional_a16,
    0xc5: partial(decode_unimplemented, 1),
    0xc6: partial(decode_unimplemented, 2),
    0xc7: partial(decode_unimplemented, 1),
    0xc8: partial(decode_unimplemented, 1),
    0xc9: partial(decode_unimplemented, 1),
    0xca: partial(decode_unimplemented, 3),
    0xcb: decode_cbprefixed,
    0xcc: decode_call_conditional_a16,
    0xcd: decode_call_unconditional_a16,
    0xce: partial(decode_unimplemented, 2),
    0xcf: partial(decode_unimplemented, 1),
    0xd0: partial(decode_unimplemented, 1),
    0xd1: partial(decode_unimplemented, 1),
    0xd2: partial(decode_unimplemented, 3),
    0xd4: decode_call_conditional_a16,
    0xd5: partial(decode_unimplemented, 1),
    0xd6: partial(decode_unimplemented, 2),
    0xd7: partial(decode_unimplemented, 1),
    0xd8: partial(decode_unimplemented, 1),
    0xd9: partial(decode_unimplemented, 1),
    0xda: partial(decode_unimplemented, 3),
    0xdc: decode_call_conditional_a16,
    0xde: partial(decode_unimplemented, 2),
    0xdf: partial(decode_unimplemented, 1),
    0xe0: decode_store_a8_a,
    0xe1: partial(decode_unimplemented, 1),
    0xe2: partial(decode_unimplemented, 2),
    0xe5: partial(decode_unimplemented, 1),
    0xe6: partial(decode_unimplemented, 2),
    0xe7: partial(decode_unimplemented, 1),
    0xe8: partial(decode_unimplemented, 2),
    0xe9: partial(decode_unimplemented, 1),
    0xea: decode_set_a16_a,
    0xee: partial(decode_unimplemented, 2),
    0xef: partial(decode_unimplemented, 1),
    0xf0: partial(decode_unimplemented, 2),
    0xf1: partial(decode_unimplemented, 1),
    0xf2: partial(decode_unimplemented, 2),
    0xf3: partial(decode_unimplemented, 1),
    0xf5: partial(decode_unimplemented, 1),
    0xf6: partial(decode_unimplemented, 2),
    0xf7: partial(decode_unimplemented, 1),
    0xf8: partial(decode_unimplemented, 2),
    0xf9: partial(decode_unimplemented, 1),
    0xfa: partial(decode_unimplemented, 3),
    0xfb: partial(decode_unimplemented, 1),
    0xfe: decode_cp_d8,
    0xff: partial(decode_unimplemented, 1),
}

def lift_il(data, addr, il):
    opcode = data[0]

    if opcode not in handlers_by_opcode:
        return None
    
    return handlers_by_opcode[opcode](data, addr, il)
