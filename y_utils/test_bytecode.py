import binascii
import os
import re
import pyevmasm
import crytic_compile
from pyevmasm import disassemble_all

bin_bytecode = crytic_compile.CryticCompile("/home/yy/sFuzz/cmake-build-debug/fuzzer/contracts/E.sol").compilation_units["/home/yy/sFuzz/cmake-build-debug/fuzzer/contracts/E.sol"].bytecodes_runtime["E"]
if bin_bytecode.endswith("0029"):
    bin_bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bin_bytecode)
if bin_bytecode.endswith("0033"):
    bin_bytecode = re.sub(r"5056fe.*?0033$", "5056", bin_bytecode)
bin_bytecode = binascii.unhexlify(bin_bytecode)
bbs = list(disassemble_all(bin_bytecode))
for i in bbs:
    print(i)
print(len(bbs))
