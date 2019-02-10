# Binary Ninja plugin for Xtensa

This repository contains a basic Binary Ninja plugin for the Xtensa instruction
set. It doesn't actually do any disassembly itself, instead it acts as glue
between Binary Ninja and radare2, which contains a full Xtensa disassembler.

You must have radare2 and r2pipe installed for this plugin to work.

For lifting to LLIL, it uses a simple ESIL -> LLIL translator.

Only Little Endian Xtensa is supported. Narrow instructions and loops are supported.
Register windows are partially supported, but Binary Ninja doesn't seem to have
proper support for windowed ABIs.

A function recognizer is included that renames subroutines that start with
an `entry` instruction to `XTFUNC` to differentiate them.

If you're feeling masochistic (or otherwise interested in debugging the ESIL->LLIL
translator), set VERBOSE_IL to True in the script. You'll get the ESIL included in
the regular disassembly, and extra useless LLIL generated like the various loop
register settings.


Useful links:

- [Radare ESIL documentation](https://radare.gitbooks.io/radare2book/disassembling/esil.html)

- [Xtensa ISA documentation](https://0x04.net/~mwk/doc/xtensa.pdf)

- @whitequark's [binja-i8086](https://github.com/whitequark/binja-i8086) is one of the most useful reference examples for a fully-featured 
architecture.

- @withzombie's [bnil-graph](https://github.com/withzombies/bnil-graph) is useful for debugging LILL.

- Amy Burnett's [Untangling Exotic Architectures with Binary 
Ninja](https://blog.ret2.io/2017/10/17/untangling-exotic-architectures-with-binary-ninja/) was also a useful reference.

- [The Binary Ninja API documentation](https://api.binary.ninja/) is a must too.

- The Binary Ninja slack is helpful for asking questions about the API.
