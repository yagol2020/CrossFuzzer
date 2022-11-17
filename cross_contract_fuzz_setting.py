"""
配置文件
"""
from enum import Enum

import loguru
import json
import pandas as pd
from datetime import datetime
from typing import List, Dict

loguru.logger.add("log/DEBUG.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="DEBUG")
loguru.logger.add("log/INFO.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="INFO")
loguru.logger.add("log/ERROR.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="ERROR")
loguru.logger.add("log/WARNING.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="WARNING")

SOLC = "/home/yy/anaconda3/envs/cross_fuzz/bin/solc"  # 用于slither分析
SOLIDITY_VERSION = "v0.4.26"
FUZZER = "fuzzer/main.py"  # docker内的main.py
PYTHON = "python3"  # docker内的python3
FUZZ_ABLE_CACHE_PATH = "cache/file_cache.csv"
MAX_FUZZ_FILE_SIZE = 1  # 一轮实验里, fuzz多少个文件?
TIME_TO_FUZZ = 10 * 1  # 单位: 秒
LARGE_SCALE_DATASETS = "/home/yy/Dataset"  # 大规模数据集的路径
SB_CURATED_LABEL_FILE = "./cache/sb_curate.csv"  # 存在标签的数据集
MAX_PROCESS_NUM = 15  # 最大多进程数量, 应该小于CPU核心数量

MAX_TRANS_LENGTH = 10  # fuzz过程中, 生成的最大事务序列长度
REPEAT_NUM = 3  # 重复次数

TOOLS = ["cross", "confuzzius", "sfuzz"]


# TOOLS = ["sfuzz"]


########
class Mode(Enum):
    """
    数据集模式
    """
    SB_CURATED = 0
    LARGE_SCALE = 1


MODE = Mode.LARGE_SCALE


########


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

class FuzzerResult:
    """
    单一fuzz结果
    """

    def __init__(self, _path, _contract_name, _coverage, _detect_result, _mode: int, _depend_contract_num: int, _total_op, _coverage_op, _transaction_count, _cross_transaction_count, _tool_name):
        self.tool_name = _tool_name
        self.path = _path
        self.contract_name = _contract_name
        self.coverage = _coverage
        self.detect_result = _detect_result
        self.mode = _mode  # 跨合约是否开启? 1开启, 2未开启
        self.depend_contract_num = _depend_contract_num  # 依赖合约数量
        self.total_op = _total_op  # 总共的操作码
        self.coverage_op = _coverage_op  # 覆盖的操作码
        self.transaction_count = _transaction_count  # 交易数量
        self.cross_transaction_count = _cross_transaction_count  # 跨合约交易数量


class Result:
    def __init__(self):
        self.res = {}  # type:Dict[str, List[FuzzerResult]]

    def append(self, _path, _fuzzer_results: List[FuzzerResult]):
        fuzz_cache_df = pd.read_csv(FUZZ_ABLE_CACHE_PATH)
        for _fuzzer_result in _fuzzer_results:
            if _fuzzer_result is None:  # 当fuzz处理失败时, 会出现None, 这里过滤这种情况
                # update fuzz able cache
                fuzz_cache_df.loc[fuzz_cache_df["path"] == _path, "enable"] = False
                fuzz_cache_df.loc[fuzz_cache_df["path"] == _path, "remark"] = "fuzz出现错误"
                fuzz_cache_df.to_csv(FUZZ_ABLE_CACHE_PATH, index=False)
                get_logger().debug("fuzz结果未生成, 已更新和保存缓存......")
                return
            temp_list = self.res.get(_path, [])
            temp_list.append(_fuzzer_result)
            self.res[_path] = temp_list
            if len(self.res[_path]) > len(TOOLS) * REPEAT_NUM:
                get_logger().warning(f"重复次数过多, 请检查{_path}的fuzz结果")

    @loguru.logger.catch()
    def inspect_exam(self, csv_path) -> int:
        """
        实验过程中检测
        返回当前Result里已有多少合法结果
        """
        get_logger().success("中间检查: 已经过滤不合法的结果, 剩余结果数量: " + str(len(self.res)))
        self.save_result(csv_path=csv_path)
        return len(self.res)

    def save_result(self, csv_path):
        """
        保存fuzz结果
        """
        if len(self.res) == 0:
            get_logger().warning("没有结果可供绘图")
            return
        cov = []

        class Coverage:
            def __init__(self, _path, _mode, _coverage, _find_bug_count, _depend_contract_num, _trans_count, _cross_trans_count):
                self.path = _path
                self.mode = _mode
                self.coverage = _coverage
                self.find_bug_count = _find_bug_count
                self.depend_contract_num = _depend_contract_num
                self.trans_count = _trans_count
                self.cross_trans_count = _cross_trans_count
                self.record_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 展开结果, 将结果平铺
        for p, rs in self.res.items():
            for ro in rs:
                cov.append(Coverage(p, ro.tool_name, ro.coverage, len(ro.detect_result), ro.depend_contract_num, ro.transaction_count, ro.cross_transaction_count))
        result_df = pd.DataFrame([c.__dict__ for c in cov])
        result_df.sort_values(by="coverage", inplace=True)
        if csv_path is not None:
            result_df.to_csv(csv_path, index=False)
