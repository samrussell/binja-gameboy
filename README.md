# Gameboy Binary Ninja plugin

## Description

A Binary Ninja plugin to load Game Boy ROMs and disassemble Game Boy architecture bytecode (Sharp LR35902).

Based on [bnGB](https://github.com/icecr4ck/bnGB) by [Hugo Porcher (icecr4ck)](https://github.com/icecr4ck).
Extended by [Carl Svensson (ZetaTwo)](https://github.com/ZetaTwo)

For a list of changes, read the [changelog](CHANGELOG).

### Improvements
* Added proper IO register symbols
* Added ISR symbols
* Fixed some incorrect branching
* Fixed some incorrect addressing modes
* Implemented LLIL lifting

### Todo
* Fix sub_d (stop disas from 0)
* Handle HALT/RESET/EI/DI opcodes in LLIL
* Handle BCD (DAA opcode and test the half carry flag)
* Thorough testing

## Installation

Either install the plugin from the plugin manager or manually clone the repository to your plugin directory.

## Minimum version

This plugin has been tested on the following versions of Binary Ninja:

* release - 3.5.4526

## References

* [Gameboy Project](https://github.com/ZetaTwo/gameboy-project)
* [Gameboy Pan Docs](http://bgb.bircd.org/pandocs.htm)
* [Gameboy opcodes](https://www.pastraiser.com/cpu/gameboy/gameboy_opcodes.html)
* [Gekkio's Game Boy Complete Technical Reference](https://gekkio.fi/files/gb-docs/gbctr.pdf)

## Testing

* [GBDK-2020](https://github.com/gbdk-2020/gbdk-2020)

## License

This plugin is released under a [MIT](LICENSE) license.
