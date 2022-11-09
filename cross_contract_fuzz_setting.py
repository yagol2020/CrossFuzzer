"""
配置文件
"""

import loguru
import json

loguru.logger.add("log/DEBUG.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="DEBUG")
loguru.logger.add("log/INFO.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="INFO")
loguru.logger.add("log/ERROR.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="ERROR")
loguru.logger.add("log/WARNING.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="WARNING")

SOLC = "/home/yy/anaconda3/envs/ConFuzzius/bin/solc"  # 用于slither分析
SOLIDITY_VERSION = "v0.4.26"
FUZZER = "fuzzer/main.py"  # docker内的main.py
PYTHON = "python3"  # docker内的python3
FUZZ_ABLE_CACHE_PATH = "cache/fuzzable_cache.csv"
DOCKER_IMAGES_NAME = "confuzzius"  # docker镜像的名字
MAX_FUZZ_FILE_SIZE = 100  # 一轮实验里, fuzz多少个文件?
TIME_TO_FUZZ = 10 * 60  # 单位: 秒
LARGE_SCALE_DATASETS = "/home/yy/Dataset"  # 大规模数据集的路径
THRESHOLD = 5  # 事务数量超过这个值, 才会被选中

MAX_PROCESS_NUM = 18  # 最大多进程数量, 应该小于CPU核心数量

MAX_TRANS_LENGTH = 10  # fuzz过程中, 生成的最大事务序列长度
REPEAT_NUM = 5  # 重复次数


def get_logger() -> loguru.logger:
    return loguru.logger


# 获得大规模数据集，合约的相关信息############
MAIN_NET_INFO_PATH = "/home/yy/Dataset/mainnet/contracts.json"
MAIN_NET_INFO = {}
lines = open(MAIN_NET_INFO_PATH).readlines()
for line in lines:
    j = json.loads(line)
    address = j["address"]
    MAIN_NET_INFO[address] = j
##########################################
