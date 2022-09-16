"""
Cross Contract Fuzz
@author : yagol
"""
import os
import random

import loguru
import json
from slither import Slither
from slither.core.declarations import Contract
from typing import List, Dict, Tuple

SOLC = "/home/yy/anaconda3/envs/ConFuzzius/bin/solc"
FUZZER = "/home/yy/ConFuzzius-Cross/fuzzer/main.py"
PYTHON = "/home/yy/anaconda3/envs/ConFuzzius/bin/python"
MAIN_NET_INFO_PATH = "/home/yy/Dataset/mainnet/contracts.json"
MAX_FUZZ_FILE_SIZE = 50  # 一轮实验里, fuzz多少个文件?


def load_ethereum_mainnet_info(_query_address) -> str:
    """
    弃用, 因为mainnet的文件名自己包含了主合约名
    """
    lines = open(MAIN_NET_INFO_PATH).readlines()
    for line in lines:
        j = json.loads(line)
        address = j["address"]
        contract_name = j["name"]
        if address == _query_address:
            return contract_name
    return "NOT_FIND"


def load_dataset(dir_path: str) -> Tuple[str, str]:
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if file.endswith(".sol"):
                if random.random() > 0.5:  # 随机跳过
                    continue
                p = os.path.join(root, file)
                if check_compile(p):
                    if "mainnet" in p:
                        contract_name = p.split("/")[-1].replace(".sol", "").split("_")[-1]
                        if contract_name != "NOT_FIND":
                            yield p, contract_name


def check_compile(file_path: str):
    try:
        Slither(file_path, solc=SOLC)
    except Exception as e:
        loguru.logger.error(f"Compile error: {file_path}, {str(e).split()[0:1]}")
        return False
    return True


def analysis_depend_contract(file_path: str, contract_name: str):
    res = []
    sl = Slither(file_path, solc=SOLC)
    for c in sl.contracts:
        if c.name == contract_name:
            continue  # 跳过主合约
        if isinstance(c, Contract):
            res.append(c.name)
    loguru.logger.info("依赖合约为: " + str(res))
    return res


class FuzzerResult:
    """
    单一fuzz结果
    """

    def __init__(self, _path, _contract_name, _coverage, _detect_result, _mode: int):
        self.path = _path
        self.contract_name = _contract_name
        self.coverage = _coverage
        self.detect_result = _detect_result
        self.mode = _mode  # 跨合约是否开启? 1开启, 2未开启


class Result:
    def __init__(self):
        self.res = {}  # type:Dict[str, List[FuzzerResult]]

    def append(self, _path, _fuzzer_result):
        if _fuzzer_result is None:  # 当fuzz处理失败时, 会出现None, 这里过滤这种情况
            return
        temp_list = self.res.get(_path, [])
        temp_list.append(_fuzzer_result)
        self.res[_path] = temp_list
        assert len(self.res[_path]) <= 2

    def remove_un_validate(self):
        """
        验证是否存在2个mode的结果, 如果不存在, 警告并删除
        """
        for p, rs in self.res.copy().items():
            if len(rs) != 2:
                loguru.logger.warning(f"存在不合法的结果, 该结果有{len(rs)}个结果, {p}")
                self.res.pop(p)

    def inspect_exam(self, inner_out=False):
        """
        实验过程中检测
        """
        self.remove_un_validate()
        loguru.logger.info("已经过滤不合法的结果, 剩余结果数量: " + str(len(self.res)))
        if inner_out:
            self.plot()
        return len(self.res)

    def plot(self, csv_path=None, plot_path=None):
        if len(self.res) == 0:
            loguru.logger.warning("没有结果可供绘图")
            return
        import pandas as pd
        import matplotlib.pyplot as plt
        import seaborn as sns
        cov = []

        class Coverage:
            def __init__(self, _path, _mode, _coverage, _index, _find_bug_count):
                self.path = _path
                self.mode = _mode
                self.coverage = _coverage
                self.index = _index
                self.find_bug_count = _find_bug_count

        index = 0
        # 展开结果, 将结果平铺
        for p, rs in self.res.items():
            if len(rs) == 2:
                cross_coverage, single_coverage = 0, 0
                cross_find_bug, single_find_bug = 0, 0
                for ro in rs:
                    temp_coverage = ro.coverage
                    bug_count = len(ro.detect_result)
                    if ro.mode == 1:
                        cross_coverage = temp_coverage
                        cross_find_bug = bug_count
                    else:
                        single_coverage = temp_coverage
                        single_find_bug = bug_count
                index += 1
                cov.append(Coverage(p, "cross", cross_coverage, index, cross_find_bug))
                cov.append(Coverage(p, "single", single_coverage, index, single_find_bug))
        df = pd.DataFrame([c.__dict__ for c in cov])
        df.sort_values(by="coverage", inplace=True)
        sns.barplot(x="index", y="coverage", hue="mode", data=df)
        if plot_path is not None:
            plt.savefig(plot_path, dpi=500)
        else:
            plt.show()
        if csv_path is not None:
            df.to_csv(csv_path, index=False)


def run_fuzzer(file_path: str, _main_contract, solc_version: str, evm_version: str, timeout: int, _depend_contracts: list, max_individual_length: int, _cross_contract: int):
    import uuid
    uuid = uuid.uuid4()
    res_path = f"/tmp/{uuid}.json"
    loguru.logger.info(f"UUID为{uuid}")
    _depend_contracts = " ".join(_depend_contracts)
    os.popen(f"{PYTHON} {FUZZER} -s {file_path} -c {_main_contract} --solc {solc_version} --evm {evm_version} -t {timeout} --cross-contract {_cross_contract} --depend-contracts {_depend_contracts} --constraint-solving 0  --result {res_path} --max-individual-length {max_individual_length}").read()
    if os.path.exists(res_path):
        res = json.load(open(res_path))[_main_contract]
        code_coverage = res["code_coverage"]["percentage"]
        detect_result = res["errors"]
        return FuzzerResult(file_path, _main_contract, code_coverage, detect_result, _cross_contract)


if __name__ == "__main__":
    r = Result()
    for path, main_contract in load_dataset("/home/yy/Dataset"):
        loguru.logger.info(f"正在处理{path}")
        depend_contracts = analysis_depend_contract(file_path=path, contract_name=main_contract)
        r_c = run_fuzzer(file_path=path, _cross_contract=1, _main_contract=main_contract, solc_version="v0.4.26", evm_version="byzantium", timeout=10, _depend_contracts=depend_contracts, max_individual_length=10)
        r_no_c = run_fuzzer(file_path=path, _cross_contract=0, _main_contract=main_contract, solc_version="v0.4.26", evm_version="byzantium", timeout=10, _depend_contracts=depend_contracts, max_individual_length=10)
        r.append(path, r_c)
        r.append(path, r_no_c)
        total_exec = r.inspect_exam(inner_out=False)
        if total_exec >= MAX_FUZZ_FILE_SIZE:
            break
    r.remove_un_validate()
    r.plot(csv_path="result.csv", plot_path="result.png")
