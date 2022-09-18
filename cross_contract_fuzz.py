"""
Cross Contract Fuzz
@author : yagol
"""
import os
import random
import time
from queue import Queue

import loguru
import json
from slither import Slither
from slither.core.declarations import Contract
from typing import List, Dict, Tuple

from slither.core.solidity_types import UserDefinedType

loguru.logger.add("DEBUG.log", rotation="1 day", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="DEBUG")
loguru.logger.add("INFO.log", rotation="1 day", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="INFO")
loguru.logger.add("ERROR.log", rotation="1 day", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="ERROR")
loguru.logger.add("WARNING.log", rotation="1 day", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="WARNING")

SOLC = "/home/yy/anaconda3/envs/ConFuzzius/bin/solc"
FUZZER = "/home/yy/ConFuzzius-Cross/fuzzer/main.py"
PYTHON = "/home/yy/anaconda3/envs/ConFuzzius/bin/python"
MAIN_NET_INFO_PATH = "/home/yy/Dataset/mainnet/contracts.json"
MAX_FUZZ_FILE_SIZE = 10  # 一轮实验里, fuzz多少个文件?
TIME_TO_FUZZ = 5  # 单位: 秒

THRESHOLD = 2  # 事务数量超过这个值, 才会被选中

loguru.logger.info(f"任务数量: {MAX_FUZZ_FILE_SIZE}, Fuzz时间: {TIME_TO_FUZZ}秒")
loguru.logger.info(f"预计执行时间: {MAX_FUZZ_FILE_SIZE * 2 * TIME_TO_FUZZ / 60}分钟")
time.sleep(1)  # 休息几秒钟, 查看任务设置


def load_ethereum_mainnet_info(_query_address) -> bool:
    """
    用于判断这个文件, 事务数量是否超过指定值
    """
    lines = open(MAIN_NET_INFO_PATH).readlines()
    for line in lines:
        j = json.loads(line)
        address = j["address"]
        trans_count = j["txcount"]  # 事务数量
        if address == _query_address and trans_count > THRESHOLD:
            loguru.logger.info(f"该合约的事务数量为: {trans_count} > {THRESHOLD}, 符合条件")
            return True
    loguru.logger.warning(f"该合约不符合事务数量阈值, 跳过")
    return False


@loguru.logger.catch()
def load_dataset(dir_path: str, debug_mode: bool = False) -> Tuple[str, str, list]:
    if debug_mode:
        yield "/home/yy/Dataset/E.sol", "E"
    else:
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".sol"):
                    if random.random() > 0.6 or "E.sol" in file:  # 随机跳过
                        continue
                    p = os.path.join(root, file)
                    address = "0x" + p.split("/")[-1].replace(".sol", "").split("_")[0]
                    contract_name = p.split("/")[-1].replace(".sol", "").split("_")[-1]
                    assert len(address) == 42, "地址的长度为2+40"
                    if load_ethereum_mainnet_info(_query_address=address) and check_compile(p):
                        _depend_contracts = analysis_depend_contract(file_path=p, _contract_name=contract_name)
                        if len(_depend_contracts) == 0 and random.random() > 0.5:
                            loguru.logger.info("由于没有依赖合约, 一定几率下, 该文件被跳过了(^_^)")
                            continue  # 如果没有依赖合约, 显示不出方法的优势, 一定几率下跳过这个
                        if "mainnet" in p:
                            yield p, contract_name, _depend_contracts


def check_compile(file_path: str):
    try:
        Slither(file_path, solc=SOLC)
    except Exception as e:
        loguru.logger.error(f"Compile error: {file_path}, {str(e).split()[0:1]}")
        return False
    return True


def analysis_depend_contract(file_path: str, _contract_name: str):
    """
    不是文件内所有的合约, 都需要部署一次
    1. 主合约继承的合约, 如果没有被[参数]/[状态变量]所调用或依赖, 那么不用部署
    2. 注意这一步需要进一步分析主合约继承的合约
    """
    res = set()  # 需要被部署的合约
    sl = Slither(file_path, solc=SOLC)
    to_be_deep_analysis = Queue()  # 这个列表里的每一个都需要分析
    to_be_deep_analysis.put(_contract_name)
    while not to_be_deep_analysis.empty():
        c = to_be_deep_analysis.get()
        contract = sl.get_contract_from_name(c)
        assert len(contract) == 1, "理论上, 根据合约名字, 只能找到一个合约"
        contract = contract[0]
        # 1. 分析被写入的状态变量
        for v in contract.all_state_variables_written:
            if not v.initialized and isinstance(v.type, UserDefinedType) and hasattr(v.type, "type") and isinstance(v.type.type, Contract):
                res.add(v.type.type.name)
                loguru.logger.debug("通过分析合约内被写入的状态变量, 发现依赖的合约: {}".format(v.type.type.name))
        for f in contract.functions:
            # 2. 分析合约内函数的参数
            for p in f.parameters:
                if isinstance(p.type, UserDefinedType) and hasattr(p.type, "type") and isinstance(p.type.type, Contract):
                    res.add(p.type.type.name)
                    loguru.logger.debug("通过分析合约内函数的参数, 发现依赖的合约: {}".format(p.type.type.name))
            # 3. 分析函数的写入变量, 如果是合约类型, 那么也需要部署
            for v in f.variables_written:
                if isinstance(v.type, UserDefinedType) and hasattr(v.type, "type") and isinstance(v.type.type, Contract):
                    res.add(v.type.type.name)
                    loguru.logger.debug("通过分析函数的写入变量(局部和状态都算), 发现依赖的合约: {}".format(v.type.type.name))
        # 3. 分析合约内的继承关系, 添加到待分析队列中
        for inherit in contract.inheritance:
            if inherit.name not in res:
                to_be_deep_analysis.put(inherit.name)
    if _contract_name in res:
        loguru.logger.debug("主合约被分析到了依赖合约中, 需要移除")
        res.remove(_contract_name)
    loguru.logger.info("依赖合约为: " + str(res) + ", 总共有: " + str(len(sl.contracts)) + "个合约, 需要部署的合约有: " + str(len(res)) + "个")
    return list(res)


class FuzzerResult:
    """
    单一fuzz结果
    """

    def __init__(self, _path, _contract_name, _coverage, _detect_result, _mode: int, _depend_contract_num: int):
        self.path = _path
        self.contract_name = _contract_name
        self.coverage = _coverage
        self.detect_result = _detect_result
        self.mode = _mode  # 跨合约是否开启? 1开启, 2未开启
        self.depend_contract_num = _depend_contract_num  # 依赖合约数量


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

    def plot(self, csv_path=None, plot_path=None, excel_path=None):
        """
        plot_path为None时, 图片保存, 不在线输出
        """
        if len(self.res) == 0:
            loguru.logger.warning("没有结果可供绘图")
            return
        import pandas as pd
        import matplotlib.pyplot as plt
        import seaborn as sns
        cov = []

        class Coverage:
            def __init__(self, _path, _mode, _coverage, _index, _find_bug_count, _depend_contract_num):
                self.path = _path
                self.mode = _mode
                self.coverage = _coverage
                self.index = _index
                self.find_bug_count = _find_bug_count
                self.depend_contract_num = _depend_contract_num

        index = 0
        # 展开结果, 将结果平铺
        for p, rs in self.res.items():
            if len(rs) == 2:
                cross_coverage, single_coverage = 0, 0
                cross_find_bug, single_find_bug = 0, 0
                cross_depend_contract_num, single_depend_contract_num = 0, 0
                for ro in rs:
                    temp_coverage = ro.coverage
                    bug_count = len(ro.detect_result)
                    depend_contract_num = ro.depend_contract_num
                    if ro.mode == 1:
                        cross_coverage = temp_coverage
                        cross_find_bug = bug_count
                        cross_depend_contract_num = depend_contract_num
                    else:
                        single_coverage = temp_coverage
                        single_find_bug = bug_count
                        single_depend_contract_num = depend_contract_num
                index += 1
                cov.append(Coverage(p, "cross", cross_coverage, index, cross_find_bug, cross_depend_contract_num))
                cov.append(Coverage(p, "single", single_coverage, index, single_find_bug, single_depend_contract_num))
        df = pd.DataFrame([c.__dict__ for c in cov])
        df.sort_values(by="coverage", inplace=True)
        sns.barplot(x="index", y="coverage", hue="mode", data=df)
        if plot_path is not None:
            plt.savefig(plot_path, dpi=500)
        else:
            plt.show()
        if csv_path is not None:
            df.to_csv(csv_path, index=False)
        if excel_path is not None:
            df.to_excel(excel_path, index=False)


def run_fuzzer(file_path: str, _main_contract, solc_version: str, evm_version: str, timeout: int, _depend_contracts: list, max_individual_length: int, _cross_contract: int):
    import uuid
    uuid = uuid.uuid4()
    res_path = f"/tmp/{uuid}.json"
    loguru.logger.info(f"UUID为{uuid}")
    _depend_contracts_str = " ".join(_depend_contracts)
    cmd = f"{PYTHON} {FUZZER} -s {file_path} -c {_main_contract} --solc {solc_version} --evm {evm_version} -t {timeout} --cross-contract {_cross_contract} --depend-contracts {_depend_contracts_str} --constraint-solving 0  --result {res_path} --max-individual-length {max_individual_length}"
    loguru.logger.debug(f"执行命令: {cmd}")
    os.popen(cmd).read()
    if os.path.exists(res_path):
        res = json.load(open(res_path))[_main_contract]
        code_coverage = res["code_coverage"]["percentage"]
        detect_result = res["errors"]
        return FuzzerResult(file_path, _main_contract, code_coverage, detect_result, _cross_contract, len(_depend_contracts))


if __name__ == "__main__":
    r = Result()
    for path, main_contract, depend_contracts in load_dataset("/home/yy/Dataset"):
        loguru.logger.info(f"正在处理{path}")
        r_c = run_fuzzer(file_path=path, _cross_contract=1, _main_contract=main_contract, solc_version="v0.4.26", evm_version="byzantium", timeout=TIME_TO_FUZZ, _depend_contracts=depend_contracts, max_individual_length=10)
        r_no_c = run_fuzzer(file_path=path, _cross_contract=2, _main_contract=main_contract, solc_version="v0.4.26", evm_version="byzantium", timeout=TIME_TO_FUZZ, _depend_contracts=[], max_individual_length=10)
        r.append(path, r_c)
        r.append(path, r_no_c)
        total_exec = r.inspect_exam(inner_out=False)
        if total_exec >= MAX_FUZZ_FILE_SIZE:
            break
    r.remove_un_validate()
    r.plot(csv_path="result.csv", plot_path="result.png", excel_path="result.xlsx")
