#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import string
import sys
import pickle
import logging
from typing import List

from eth import Chain, constants
from eth.chains.mainnet import (
    MAINNET_GENESIS_HEADER,
    HOMESTEAD_MAINNET_BLOCK,
    TANGERINE_WHISTLE_MAINNET_BLOCK,
    SPURIOUS_DRAGON_MAINNET_BLOCK,
    BYZANTIUM_MAINNET_BLOCK,
    PETERSBURG_MAINNET_BLOCK
)
from eth.constants import ZERO_ADDRESS, CREATE_CONTRACT_ADDRESS
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth.rlp.accounts import Account
from eth.rlp.headers import BlockHeader
from eth.tools.logging import DEBUG2_LEVEL_NUM
from eth.validation import validate_uint256
from eth.vm.spoof import SpoofTransaction
from eth_utils import to_canonical_address, decode_hex, encode_hex
from web3 import HTTPProvider
from web3 import Web3

from .storage_emulation import (
    FrontierVMForFuzzTesting,
    HomesteadVMForFuzzTesting,
    TangerineWhistleVMForFuzzTesting,
    SpuriousDragonVMForFuzzTesting,
    ByzantiumVMForFuzzTesting,
    PetersburgVMForFuzzTesting
)
# 获取根目录
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/../'
# 将根目录添加到path中
sys.path.append(BASE_DIR)
from fuzzer.utils import settings
from fuzzer.utils.utils import initialize_logger
from eth_abi import encode_abi


class InstrumentedEVM:
    def __init__(self, eth_node_ip=None, eth_node_port=None) -> None:
        chain_class = Chain.configure(
            __name__='Blockchain',
            vm_configuration=(
                (constants.GENESIS_BLOCK_NUMBER, FrontierVMForFuzzTesting),
                (HOMESTEAD_MAINNET_BLOCK, HomesteadVMForFuzzTesting),
                (TANGERINE_WHISTLE_MAINNET_BLOCK, TangerineWhistleVMForFuzzTesting),
                (SPURIOUS_DRAGON_MAINNET_BLOCK, SpuriousDragonVMForFuzzTesting),
                (BYZANTIUM_MAINNET_BLOCK, ByzantiumVMForFuzzTesting),
                (PETERSBURG_MAINNET_BLOCK, PetersburgVMForFuzzTesting),
            ),
        )

        class MyMemoryDB(MemoryDB):
            def __init__(self) -> None:
                self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()}

            def rst(self) -> None:
                self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()}

        if eth_node_ip and eth_node_port and settings.REMOTE_FUZZING:
            self.w3 = Web3(HTTPProvider('http://%s:%s' % (eth_node_ip, eth_node_port)))
        else:
            self.w3 = None
        self.chain = chain_class.from_genesis_header(AtomicDB(MyMemoryDB()), MAINNET_GENESIS_HEADER)
        self.logger = initialize_logger("EVM")
        self.accounts = list()
        self.snapshot = None
        self.vm = None

    def get_block_by_blockid(self, block_identifier):
        validate_uint256(block_identifier)
        return self.w3.eth.getBlock(block_identifier)

    def get_cached_block_by_id(self, block_number):
        block = None
        with open(os.path.dirname(os.path.abspath(__file__)) + "/" + ".".join([str(block_number), "block"]), "rb") as f:
            block = pickle.load(f)
        return block

    @property
    def storage_emulator(self):
        return self.vm.state._account_db

    def set_vm(self, block_identifier='latest'):
        _block = None
        if self.w3:
            if block_identifier == 'latest':
                block_identifier = self.w3.eth.blockNumber
            validate_uint256(block_identifier)
            _block = self.w3.eth.getBlock(block_identifier)
        if not _block:
            if block_identifier in [HOMESTEAD_MAINNET_BLOCK, BYZANTIUM_MAINNET_BLOCK, PETERSBURG_MAINNET_BLOCK]:
                _block = self.get_cached_block_by_id(block_identifier)
            else:
                self.logger.error("Unknown block identifier.")
                sys.exit(-4)
        block_header = BlockHeader(difficulty=_block.difficulty,
                                   block_number=_block.number,
                                   gas_limit=_block.gasLimit,
                                   timestamp=_block.timestamp,
                                   coinbase=ZERO_ADDRESS,  # default value
                                   parent_hash=_block.parentHash,
                                   uncles_hash=_block.uncles,
                                   state_root=_block.stateRoot,
                                   transaction_root=_block.transactionsRoot,
                                   receipt_root=_block.receiptsRoot,
                                   bloom=0,  # default value
                                   gas_used=_block.gasUsed,
                                   extra_data=_block.extraData,
                                   mix_hash=_block.mixHash,
                                   nonce=_block.nonce)
        self.vm = self.chain.get_vm(block_header)

    def execute(self, tx, debug=True):  # debug默认是False
        if debug:
            logging.getLogger('eth.vm.computation.Computation')
            logging.basicConfig(level=DEBUG2_LEVEL_NUM)
        return self.vm.state.apply_transaction(tx)

    def reset(self):
        self.storage_emulator._raw_store_db.wrapped_db.rst()

    def create_fake_account(self, address, nonce=0, balance=settings.ACCOUNT_BALANCE, code='', storage=None):
        if storage is None:
            storage = {}
        address = to_canonical_address(address)
        account = Account(nonce=nonce, balance=balance)
        self.vm.state._account_db._set_account(address, account)
        if code and code != '':
            self.vm.state._account_db.set_code(address, code)
        if storage:
            for k, v in storage.items():
                self.vm.state._account_db.set_storage(address, int.from_bytes(decode_hex(k), byteorder="big"), int.from_bytes(decode_hex(v), byteorder="big"))
        self.logger.debug("Created account %s with balance %s", encode_hex(address), account.balance)
        return encode_hex(address)

    def has_account(self, address):
        address = to_canonical_address(address)
        return self.vm.state._account_db._has_account(address)

    def deploy_contract(self, creator, bin_code, amount=0, gas=settings.GAS_LIMIT, gas_price=settings.GAS_PRICE, debug=False, deploy_args: List[str] = None):
        """
        部署合约
        """
        if deploy_args is not None:
            assert len(deploy_args) % 3 == 0, "deploy_args必须是3的倍数, [name, type, name对应的contract或者YA_DO_NOT_KNOW]"
            encode_types = []
            encode_values = []
            for i in range(0, len(deploy_args), 3):
                param_name, param_type, param_value = deploy_args[i:i + 3]
                if param_type == "address" and param_value != "YA_DO_NOT_KNOW":
                    encode_types.append(param_type)
                    encode_values.append(settings.TRANS_INFO[param_value])
                elif param_type == "address" and param_value == "YA_DO_NOT_KNOW":
                    encode_types.append(param_type)
                    encode_values.append(creator)
                elif param_type.startswith("uint") and param_value == "YA_DO_NOT_KNOW":
                    uint_size = int(param_type[4:])
                    encode_types.append(param_type)
                    encode_values.append(0)
                elif param_type == "bool" and param_value == "YA_DO_NOT_KNOW":
                    encode_types.append(param_type)
                    encode_values.append(random.choice([True, False]))
                elif param_type == "string" and param_value == "YA_DO_NOT_KNOW":
                    encode_types.append(param_type)
                    encode_values.append("".join(random.sample(string.ascii_letters + string.digits, 8)))
                elif param_type.startswith("bytes") and param_value == "YA_DO_NOT_KNOW":
                    if param_type == "bytes":
                        bytes_size = random.randint(1, 32)
                    else:
                        bytes_size = int(param_type[5:])
                    encode_types.append(param_type)
                    encode_values.append(bytearray(random.getrandbits(8) for _ in range(bytes_size)))
                elif param_type.startswith("int") and param_value == "YA_DO_NOT_KNOW":
                    int_size = int(param_type[3:])
                    encode_types.append(param_type)
                    encode_values.append(0)
            self.logger.info(f"encode_values: {encode_values}")
            bin_code += encode_abi(encode_types, encode_values).hex()
        nonce = self.vm.state.get_nonce(decode_hex(creator))
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=CREATE_CONTRACT_ADDRESS,
            value=amount,
            data=decode_hex(bin_code),
        )
        tx = SpoofTransaction(tx, from_=decode_hex(creator))
        result = self.execute(tx, debug=debug)
        address = to_canonical_address(encode_hex(result.msg.storage_address))
        self.storage_emulator.set_balance(address, 1)
        return result

    def deploy_transaction(self, input, gas_price=settings.GAS_PRICE, debug=False):
        transaction = input["transaction"]
        from_account = decode_hex(transaction["from"])
        nonce = self.vm.state.get_nonce(from_account)
        try:
            to = decode_hex(transaction["to"])
        except:
            to = transaction["to"]
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=transaction["gaslimit"],
            to=to,
            value=transaction["value"],
            data=decode_hex(transaction["data"]),
        )
        tx = SpoofTransaction(tx, from_=from_account)

        block = input["block"]
        if "timestamp" in block and block["timestamp"] is not None:
            self.vm.state.fuzzed_timestamp = block["timestamp"]
        else:
            self.vm.state.fuzzed_timestamp = None
        if "blocknumber" in block and block["blocknumber"] is not None:
            self.vm.state.fuzzed_blocknumber = block["blocknumber"]
        else:
            self.vm.state.fuzzed_blocknumber = None

        global_state = input["global_state"]
        if "balance" in global_state and global_state["balance"] is not None:
            self.vm.state.fuzzed_balance = global_state["balance"]
        else:
            self.vm.state.fuzzed_balance = None

        if "call_return" in global_state and global_state["call_return"] is not None \
                and len(global_state["call_return"]) > 0:
            self.vm.state.fuzzed_call_return = global_state["call_return"]
        if "extcodesize" in global_state and global_state["extcodesize"] is not None \
                and len(global_state["extcodesize"]) > 0:
            self.vm.state.fuzzed_extcodesize = global_state["extcodesize"]

        environment = input["environment"]
        if "returndatasize" in environment and environment["returndatasize"] is not None:
            self.vm.state.fuzzed_returndatasize = environment["returndatasize"]

        self.storage_emulator.set_balance(from_account, settings.ACCOUNT_BALANCE)
        return self.execute(tx, debug=debug)

    def get_balance(self, address):
        return self.storage_emulator.get_balance(address)

    def get_code(self, address):
        return self.storage_emulator.get_code(address)

    def set_code(self, address, code):
        return self.storage_emulator.set_code(address, code)

    def create_snapshot(self):
        self.snapshot = self.storage_emulator.record()
        self.storage_emulator.set_snapshot(self.snapshot)

    def restore_from_snapshot(self):
        self.storage_emulator.discard(self.snapshot)

    def get_accounts(self):
        return [encode_hex(x) for x in self.storage_emulator._raw_store_db.wrapped_db["account"].keys()]

    def set_vm_by_name(self, EVM_VERSION):
        if EVM_VERSION == "homestead":
            self.set_vm(HOMESTEAD_MAINNET_BLOCK)
        elif EVM_VERSION == "byzantium":
            self.set_vm(BYZANTIUM_MAINNET_BLOCK)
        elif EVM_VERSION == "petersburg":
            self.set_vm(PETERSBURG_MAINNET_BLOCK)
        else:
            raise Exception("Unknown EVM version, please choose either 'homestead', 'byzantium' or 'petersburg'.")

    def create_fake_accounts(self):
        self.accounts.append(self.create_fake_account("0xcafebabecafebabecafebabecafebabecafebabe"))
        for address in settings.ATTACKER_ACCOUNTS:
            self.accounts.append(self.create_fake_account(address))
