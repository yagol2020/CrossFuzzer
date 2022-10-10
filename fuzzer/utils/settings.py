#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import time
from datetime import datetime

# Ethereum VM ('homestead', 'byzantium' or 'petersburg')
EVM_VERSION = "petersburg"
# Size of population
POPULATION_SIZE = None
# Number of generations
GENERATIONS = 10
# Global timeout in seconds
GLOBAL_TIMEOUT = None
# Probability of crossover
PROBABILITY_CROSSOVER = 0.9
# Probability of mutation
PROBABILITY_MUTATION = 0.1
# Maximum number of symbolic execution calls before restting population
MAX_SYMBOLIC_EXECUTION = 10
# Solver timeout in milliseconds
SOLVER_TIMEOUT = 100
# List of attacker accounts
ATTACKER_ACCOUNTS = ["0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]
# Default gas limit for sending transactions
GAS_LIMIT = 450000000
# Default gas price for sending transactions
GAS_PRICE = 10
# Default account balance
ACCOUNT_BALANCE = 100000000 * (10 ** 18)
# Maximum length of individuals
MAX_INDIVIDUAL_LENGTH = 5
# Logging level
LOGGING_LEVEL = logging.INFO
# Block height
BLOCK_HEIGHT = 'latest'
# RPC Host
RPC_HOST = 'localhost'
# RPC Port
RPC_PORT = 8545
# True = Remote fuzzing, False = Local fuzzing
REMOTE_FUZZING = False
# True = Environmental instrumentation enabled, False = Environmental instrumentation disabled
ENVIRONMENTAL_INSTRUMENTATION = True
# trans_info存储的位置, 默认为/tmp/ConFuzzius_trans.json
TRANS_INFO_JSON_PATH = "/tmp/ConFuzzius_trans.json"
# 在内存中加载trans_info, 避免重复I/O
TRANS_INFO = {"start_time": str(datetime.now())}  # 用于统计覆盖率时, 跳过无关合约
# 主合约名称
MAIN_CONTRACT_NAME = ""
# 是否输出trans_info
OUTPUT_TRANS_INFO = False
# SOLC地址, 用于cross slither
SOLC_PATH_CROSS = ""
# SURYA地址, 用于cross CFG
SURYA_PATH_CROSS = ""
# 记录跨合约事务的执行数量
CROSS_TRANS_EXEC_COUNT = 0
# 控制事务序列的生成策略
TRANS_MODE = "origin"
