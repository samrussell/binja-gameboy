import json
import os
import re
import struct

from binaryninja.architecture import Architecture
from binaryninja.enums import InstructionTextTokenType, FlagRole, BranchType, LowLevelILFlagCondition
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.log import log_info
from binaryninja.lowlevelil import LowLevelILFunction, LowLevelILLabel
from .lifting import lift_il, lift_flag_il


class LR35902(Architecture):
    name = 'LR35902'
    address_size = 2        # 16-bit addresses
    default_int_size = 1    # 1-byte integers
    instr_alignment = 1     # no instruction alignment
    max_instr_length = 3    # maximum length (opcodes 1-2, operans 0-2 bytes)

    regs = {
        # Main registers
        'A': RegisterInfo('A', 1),
        #'AF': RegisterInfo('AF', 2),
        'BC': RegisterInfo('BC', 2),
        'DE': RegisterInfo('DE', 2),
        'HL': RegisterInfo('HL', 2),

        'SP': RegisterInfo('SP', 2),
        'PC': RegisterInfo('PC', 2),

        # Sub registers
        #'A': RegisterInfo('AF', 1, 1),
        #'Flags': RegisterInfo('AF', 0),
        'B': RegisterInfo('BC', 1, 1),
        'C': RegisterInfo('BC', 1, 0),
        'D': RegisterInfo('DE', 1, 1),
        'E': RegisterInfo('DE', 1, 0),
        'H': RegisterInfo('HL', 1, 1),
        'L': RegisterInfo('HL', 1, 0),
    }

    flags = ["z", "n", "h", "c", "i"]
    flag_write_types = ["*", "znh", "nhc", "nh"]
    flag_roles = {
        'z': FlagRole.ZeroFlagRole,
        'n': FlagRole.SpecialFlagRole,
        'h': FlagRole.HalfCarryFlagRole,
        'c': FlagRole.CarryFlagRole,
        'i': FlagRole.SpecialFlagRole,
    }
    flags_written_by_flag_write_type = {
        "*": ["z", "n", "h", "c"],
        "znh": ["z", "n", "h"],
        "nhc": ["n", "h", "c"],
        "nh": ["n", "h"],
    }
    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_E:   ['z'],
        LowLevelILFlagCondition.LLFC_NE:  ['z'],
        LowLevelILFlagCondition.LLFC_ULT:  ['c'],
        LowLevelILFlagCondition.LLFC_UGE:  ['c'],
    }

    stack_pointer = "SP"

    INVALID_INS = (None, None, None, None, None)
    conditions_strings = ['C', 'NC', 'Z', 'NZ']
    bit_instructions = ['BIT', 'RES', 'SET']

    # (address, name)
    IO_REGISTERS = {
        0xFF00: "P1",
        0xFF01: "SB",
        0xFF02: "SC",
        0xFF04: "DIV",
        0xFF05: "TIMA",
        0xFF06: "TMA",
        0xFF07: "TAC",
        0xFF0F: "IF",
        0xFF10: "NR10",
        0xFF11: "NR11",
        0xFF12: "NR12",
        0xff13: "NR13",
        0xFF14: "NR14",
        0xFF16: "NR21",
        0xFF17: "NR22",
        0xFF18: "NR23",
        0xFF19: "NR24",
        0xFF1A: "NR30",
        0xFF1B: "NR31",
        0xFF1C: "NR32",
        0xFF1D: "NR33",
        0xFF1E: "NR34",
        0xFF20: "NR41",
        0xFF21: "NR42",
        0xFF22: "NR43",
        0xFF23: "NR44",
        0xFF24: "NR50",
        0xFF25: "NR51",
        0xFF26: "NR52",

        0xFF30: "WAV0",
        0xFF31: "WAV1",
        0xFF32: "WAV2",
        0xFF33: "WAV3",
        0xFF34: "WAV4",
        0xFF35: "WAV5",
        0xFF36: "WAV6",
        0xFF37: "WAV7",
        0xFF38: "WAV8",
        0xFF39: "WAV9",
        0xFF3A: "WAVA",
        0xFF3B: "WAVB",
        0xFF3C: "WAVC",
        0xFF3D: "WAVD",
        0xFF3E: "WAVE",
        0xFF3F: "WAVF",

        0xFF40: "LCDC",
        0xFF41: "STAT",
        0xFF42: "SCY",
        0xFF43: "SCX",
        0xFF44: "LY",
        0xFF45: "LYC",
        0xFF46: "DMA",
        0xFF47: "BGP",
        0xFF48: "OBP0",
        0xFF49: "OBP1",
        0xFF4A: "WY",
        0xFF4B: "WX",
        0xFF4D: "KEY1",
        0xFF4F: "VBK",
        0xFF51: "HDMA1",
        0xFF52: "HDMA2",
        0xFF53: "HDMA3",
        0xFF54: "HDMA4",
        0xFF55: "HDMA5",
        0xFF56: "RP",
        0xFF68: "BCPS",
        0xFF69: "BCPD",
        0xFF6A: "OCPS",
        0xFF6B: "OCPD",
        0xFF70: "SVBK",
        0xFFFF: "IE",
    }

    def __init__(self):
        Architecture.__init__(self)

        basepath = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(basepath, 'opcodes.json')) as fin:
            self.opcodes = json.load(fin)


    def _get_io_register(self, addr):
        if addr in range(0xFF80, 0xFFFF):
            return f'HRAM_{addr-0xFF80:02X}'
        elif addr in self.IO_REGISTERS:
            return self.IO_REGISTERS[addr]
        else:
            # should not happen, probably bad disassembly but return something
            return "UNK_%04X" % addr

    def _decode_instruction(self, data: bytes, addr: int):
        if len(data[:1]) == 0:
            return self.INVALID_INS
        if data[0] == 0xCB:
            if len(data[:2]) < 2:
                return self.INVALID_INS
            ins_entry = self.opcodes['cbprefixed'].get('%#x' % data[1], None)
        else:
            ins_entry = self.opcodes['unprefixed'].get('%#x' % data[0], None)

        if not ins_entry:
            return self.INVALID_INS
        
        if len(data[:3]) < ins_entry['length']:
            return self.INVALID_INS

        ins_operands = []
        if 'operand1' in ins_entry:
            ins_operands.append(ins_entry['operand1'])
        if 'operand2' in ins_entry:
            ins_operands.append(ins_entry['operand2'])
        ins_flags = [f.lower() for f in ins_entry['flags']]
        if ins_entry['length'] == 2:
            ins_value = data[1]
        elif ins_entry['length'] == 3:
            ins_value = struct.unpack('<H', data[1:3])[0]
        else:
            ins_value = None

        return ins_entry['mnemonic'], ins_entry['length'], ins_operands, ins_flags, ins_value

    def _get_token(self, mnemonic: str, operand: str, data: bytes, addr: int, instruction_length: int):
        if mnemonic == 'STOP':
            return [InstructionTextToken(InstructionTextTokenType.TextToken, '0')]
        if mnemonic == 'RST':
            value = bytes.fromhex(operand[:2])[0]
            return [InstructionTextToken(InstructionTextTokenType.AddressDisplayToken, f"irs_usr{value//8}", value)]

        result = []
        depth = 0
        atoms = [t for t in re.split(r'([()\+\-])', operand) if t]

        for atom in atoms:
            if atom == 'd8':
                value = data[1]
                result.append(InstructionTextToken(
                    InstructionTextTokenType.PossibleValueToken, f'{value:#04x}', value))
            elif atom == 'd16':
                value = struct.unpack('<H', data[1:3])[0]
                result.append(InstructionTextToken(
                    InstructionTextTokenType.PossibleAddressToken, f'{value:#06x}', value))
            elif atom == 'a8':
                value = struct.unpack('<B', data[1:2])[0]
                try:
                    result.append(InstructionTextToken(
                        InstructionTextTokenType.DataSymbolToken, self._get_io_register(0xFF00+value), 0xFF00+value))
                except:
                    raise ValueError(
                        f'Invalid IO register offset {value} in {mnemonic} {atoms} at addr {addr:#0x}')
            elif atom == 'a16':
                value = struct.unpack('<H', data[1:3])[0]
                result.append(InstructionTextToken(
                    InstructionTextTokenType.PossibleAddressToken, f'{value:#06x}', value))
            elif atom == 'r8':
                value = struct.unpack('<b', data[1:2])[0]
                if atoms[0] == 'SP':  # SP+r8
                    result.append(InstructionTextToken(
                        InstructionTextTokenType.PossibleAddressToken, f'{value:#04x}', value))
                else:  # r8
                    result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken,
                                                       f'{addr+value+instruction_length:#06x}', addr+instruction_length+value))
            elif atom == '(':
                depth += 1
                result.append(InstructionTextToken(
                    InstructionTextTokenType.BeginMemoryOperandToken, atom))
            elif atom == ')':
                depth -= 1
                if depth < 0:
                    raise ValueError(f'Unbalanced parenthesis in {atoms}')
                result.append(InstructionTextToken(
                    InstructionTextTokenType.EndMemoryOperandToken, atom))
            elif atom in '+-':
                result.append(InstructionTextToken(
                    InstructionTextTokenType.TextToken, atom))
            elif atom in self.conditions_strings and mnemonic in ['CALL', 'RET', 'JR', 'JP']:
                result.append(InstructionTextToken(
                    InstructionTextTokenType.TextToken, atom))
            elif atom in self.regs.keys():
                result.append(InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, atom))
            elif atom == 'AF':
                # sorry, downside to having fake regs in lifter
                result.append(InstructionTextToken(
                    InstructionTextTokenType.RegisterToken, atom))
            elif mnemonic in self.bit_instructions and atom in [str(x) for x in range(8)]:
                result.append(InstructionTextToken(
                    InstructionTextTokenType.TextToken, atom))
            else:
                raise ValueError(
                    f'Unrecognized atom {atom} in {atoms} for instruction {mnemonic}')

        return result

    def get_instruction_info(self, data: bytes, addr: int):
        ins_mnem, ins_len, _, _, _ = self._decode_instruction(data, addr)
        if not ins_mnem:
            return None

        result = InstructionInfo()
        result.length = ins_len
        ins_end = addr + ins_len

        opcode = data[0]
        if ins_mnem == 'JR':
            offset = struct.unpack('<b', data[1:2])[0]
            if opcode == 0x28 or opcode == 0x38:
                result.add_branch(BranchType.TrueBranch, ins_end + offset)
                result.add_branch(BranchType.FalseBranch, ins_end)
            elif opcode == 0x20 or opcode == 0x30:
                result.add_branch(BranchType.TrueBranch, ins_end)
                result.add_branch(BranchType.FalseBranch, ins_end + offset)
            else:
                result.add_branch(
                    BranchType.UnconditionalBranch, ins_end + offset)
        elif ins_mnem == 'JP':
            if opcode == 0xe9:
                result.add_branch(BranchType.IndirectBranch)
            else:
                arg = struct.unpack('<H', data[1:3])[0]
                if opcode == 0xca or opcode == 0xda:
                    result.add_branch(BranchType.TrueBranch, arg)
                    result.add_branch(BranchType.FalseBranch, ins_end)
                elif opcode == 0xc2 or opcode == 0xd2:
                    result.add_branch(BranchType.TrueBranch, ins_end)
                    result.add_branch(BranchType.FalseBranch, arg)
                else:
                    result.add_branch(BranchType.UnconditionalBranch, arg)
        elif ins_mnem == 'RET':
            result.add_branch(BranchType.FunctionReturn)
        elif ins_mnem == 'RETI':
            result.add_branch(BranchType.FunctionReturn)
        elif ins_mnem == 'CALL':
            result.add_branch(BranchType.CallDestination,
                              struct.unpack("<H", data[1:3])[0])
        return result

    def get_instruction_text(self, data, addr):
        ins_mnem, ins_len, operands, _, _ = self._decode_instruction(
            data, addr)
        if ins_mnem is None:
            return None

        tokens = []
        tokens.append(InstructionTextToken(
            InstructionTextTokenType.InstructionToken, ins_mnem.lower()))
        if len(operands) >= 1:
            tokens.append(InstructionTextToken(
                InstructionTextTokenType.IndentationToken, ''.rjust(8 - len(ins_mnem))))
            tokens += self._get_token(ins_mnem,
                                      operands[0], data, addr, ins_len)
            if len(operands) == 2:
                tokens.append(InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ', '))
                tokens += self._get_token(ins_mnem,
                                          operands[1], data, addr, ins_len)
        return tokens, ins_len

    def get_instruction_low_level_il(self, data, addr, il: LowLevelILFunction):
        return lift_il(data, addr, il)
    
    def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
        flag_il = lift_flag_il(op, size, write_type, flag, operands, il)
        if flag_il:
            return flag_il

        return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)

