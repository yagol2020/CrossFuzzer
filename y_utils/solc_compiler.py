import re

import solcx
from semantic_version import Version


def compile(solc_version, evm_version, source_code_file):
    with open(source_code_file, 'r') as file:
        source_code = file.read()
    solcx.set_solc_version(Version(solc_version), True)
    out = solcx.compile_standard({
        'language': 'Solidity',
        'sources': {source_code_file: {'content': source_code}},
        'settings': {
            "optimizer": {
                "enabled": True,
                "runs": 200
            },
            "evmVersion": evm_version,
            "outputSelection": {
                source_code_file: {
                    "*":
                        [
                            "abi",
                            "evm.deployedBytecode",
                            "evm.bytecode.object",
                            "evm.legacyAssembly",
                        ],
                }
            }
        }
    }, allow_paths='.')
    return out


def remove_swarm_hash(bytecode):
    if isinstance(bytecode, str):
        if bytecode.endswith("0029"):
            bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)
        if bytecode.endswith("0033"):
            bytecode = re.sub(r"5056fe.*?0033$", "5056", bytecode)
    return bytecode


def get_pcs(bytecode):
    bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))
    i = 0
    pcs = []
    while i < len(bytecode):
        opcode = bytecode[i]
        pcs.append(i)
        if 96 <= opcode <= 127:  # PUSH
            size = opcode - 96 + 1
            i += size
        i += 1
    if len(pcs) == 0:
        pcs = [0]
    return pcs
