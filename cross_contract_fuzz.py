"""
Cross Contract Fuzz
@author : yagol
"""
import multiprocessing
import os
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime
from queue import Queue
import docker

import loguru
import json
from slither import Slither
from slither.core.declarations import Contract
from typing import List, Dict, Tuple

from slither.core.solidity_types import UserDefinedType

loguru.logger.add("log/DEBUG.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="DEBUG")
loguru.logger.add("log/INFO.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="INFO")
loguru.logger.add("log/ERROR.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="ERROR")
loguru.logger.add("log/WARNING.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="WARNING")

SOLC = "/home/yy/anaconda3/envs/ConFuzzius/bin/solc"  # 用于slither分析
FUZZER = "fuzzer/main.py"  # docker内的main.py
PYTHON = "python3"  # docker内的python3
MAIN_NET_INFO_PATH = "/home/yy/Dataset/mainnet/contracts.json"  # 用于获得每个合约的trans数量
DOCKER_IMAGES_NAME = "confuzzius"  # docker镜像的名字
MAX_FUZZ_FILE_SIZE = 200  # 一轮实验里, fuzz多少个文件?
TIME_TO_FUZZ = 20 * 60  # 单位: 秒

RESULT_APPEND_MODE = False  # 追加模式?非追加模式下, 直接生成全新的文件, 如果启用了中间inspect, 则每次生成一个新的文件

THRESHOLD = 5  # 事务数量超过这个值, 才会被选中

MAX_PROCESS_NUM = 15  # 最大多进程数量, 应该小于CPU核心数量

MAX_TRANS_LENGTH = 10  # fuzz过程中, 生成的最大事务序列长度

SOLIDITY_VERSION = "v0.4.26"

loguru.logger.info(f"任务数量: {MAX_FUZZ_FILE_SIZE}, Fuzz时间: {TIME_TO_FUZZ}秒")
loguru.logger.info(f"预计最低执行时间: {MAX_FUZZ_FILE_SIZE * 2 * TIME_TO_FUZZ / 60}分钟, 即{MAX_FUZZ_FILE_SIZE * 2 * TIME_TO_FUZZ / 60 / 60}小时")
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
        yield "/home/yy/Dataset/E.sol", "E", ["M", "K"]
    else:
        paths = []  # 所有sol文件的路径, 用于打乱, 否则总是那么几个文件
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".sol"):
                    p = os.path.join(root, file)
                    paths.append(p)
        random.shuffle(paths)
        for p in paths:
            if len(os.path.basename(p).replace(".sol", "").split("_")) != 2:
                continue
            # if p != "/home/yy/Dataset/mainnet/1d/1d4ccc31dab6ea20f461d329a0562c1c58412515_TalaoToken.sol":
            #     continue
            address = "0x" + os.path.basename(p).replace(".sol", "").split("_")[0]
            contract_name = os.path.basename(p).replace(".sol", "").split("_")[1]
            assert len(address) == 42, "地址的长度为2 + 40"
            if load_ethereum_mainnet_info(_query_address=address) and check_compile(p) and check_surya(p):
                _depend_contracts = analysis_depend_contract(file_path=p, _contract_name=contract_name)
                if len(_depend_contracts) == 0 and random.randint(0, 50) > 40:
                    loguru.logger.debug("跳过非跨合约文件.......")
                    continue  # 跳过非跨合约的文件, 这类文件没有比较的意义了
                if "mainnet" in p:
                    yield p, contract_name, _depend_contracts


def check_compile(file_path: str):
    try:
        Slither(file_path, solc=SOLC)
    except Exception as e:
        loguru.logger.error(f"Compile error: {file_path}, {str(e).split()[0:1]}")
        return False
    return True


def check_surya(file_path: str):
    HOST_SURYA_PATH = "/usr/local/bin/surya"
    test_surya_cmd = f"{HOST_SURYA_PATH} graph {file_path}"
    try:
        output = subprocess.check_output(test_surya_cmd, shell=True)
        if output == b'':
            raise Exception("surya error")
    except Exception as e:
        loguru.logger.error(f"Surya error: {file_path}, {str(e).split()[0:1]}")
        return False
    return True


def analysis_depend_contract(file_path: str, _contract_name: str) -> list:
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
                if hasattr(v, "type") and isinstance(v.type, UserDefinedType) and hasattr(v.type, "type") and isinstance(v.type.type, Contract):
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

    def inspect_exam(self, inner_out=False, csv_path=None) -> int:
        """
        实验过程中检测
        返回当前Result里已有多少合法结果
        """
        self.remove_un_validate()
        loguru.logger.success("中间检查: 已经过滤不合法的结果, 剩余结果数量: " + str(len(self.res)))
        if inner_out and csv_path is not None and RESULT_APPEND_MODE is False:  # 如果启动了追加模式, 不要进入plot函数增加csv文件
            self.plot(csv_path=csv_path, online_plot=False)
        return len(self.res)

    def plot(self, csv_path=None, plot_path=None, online_plot=False):
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
                self.record_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
            if online_plot:
                plt.show()
        if csv_path is not None:
            if RESULT_APPEND_MODE:
                df.to_csv(csv_path, mode="a", header=False, index=False)
            else:
                df.to_csv(csv_path, index=False)


def run_fuzzer(_file_path: str, _main_contract, solc_version: str, evm_version: str, timeout: int, _depend_contracts: list, max_individual_length: int, _cross_contract: int):
    import uuid
    uuid = uuid.uuid4()
    res_path = f"/tmp/ConFuzzius-{uuid}.json"
    file_path = f"/tmp/ConFuzzius-{uuid}.sol"
    shutil.copyfile(_file_path, file_path)  # 移动到/tmp里, 这个是和docker的共享目录
    loguru.logger.info(f"UUID为{uuid}")
    if _cross_contract == 1:
        depend_contracts_str = " ".join(_depend_contracts)
        cmd = f"{PYTHON} {FUZZER} -s {file_path} -c {_main_contract} --solc {solc_version} --evm {evm_version} -t {timeout} --cross-contract {_cross_contract} --depend-contracts {depend_contracts_str} --constraint-solving 0  --result {res_path} --max-individual-length {max_individual_length} --solc-path-cross /usr/local/bin/solc --surya-path-cross /usr/local/bin/surya"
        run_in_docker(cmd, _images="confuzzius-cross")
    else:
        cmd = f"{PYTHON} {FUZZER} -s {file_path} -c {_main_contract} --solc {solc_version} --evm {evm_version} -t {timeout} --constraint-solving 0 --result {res_path} --max-individual-length {max_individual_length}"
        run_in_docker(cmd, _images="confuzzius-origin")
    if os.path.exists(res_path):
        res = json.load(open(res_path))[_main_contract]
        code_coverage = res["code_coverage"]["percentage"]
        detect_result = res["errors"]
        return FuzzerResult(file_path, _main_contract, code_coverage, detect_result, _cross_contract, len(_depend_contracts))
    else:
        loguru.logger.warning(f"执行命令: {cmd}, 模式为 {_cross_contract} 时, 未能生成结果文件, 请检查")
        return None


def run_in_docker(cmd: str, _images: str):
    """
    基于docker运行cmd
    """
    try:
        client = docker.from_env()
        container = client.containers.run(image=_images, volumes=['/tmp:/tmp'], command=cmd, detach=True)
        loguru.logger.debug(f"执行命令: {cmd}, container id: {container.id}, image: {_images}")
        result = container.wait()
        output = container.logs()
        if output is None or result is None or (result is not None and "Error" in result.items() and result["Error"] is not None):
            loguru.logger.warning(f"docker 执行命令 {cmd} 时发生错误, 错误信息: {result}")
        container.stop()
        container.remove()
    except BaseException as be:
        loguru.logger.error(f"docker运行命令: {cmd} 时出错: {be}")
        sys.exit(-1)


if __name__ == "__main__":
    r = Result()
    mp_result = []
    with multiprocessing.Pool(processes=MAX_PROCESS_NUM) as pool:
        for path, main_contract, depend_contracts in load_dataset("/home/yy/Dataset"):
            loguru.logger.info(f"正在处理{path}")
            r_c = pool.apply_async(run_fuzzer, args=(path, main_contract, SOLIDITY_VERSION, "byzantium", TIME_TO_FUZZ, depend_contracts, MAX_TRANS_LENGTH, 1))
            r_no_c = pool.apply_async(run_fuzzer, args=(path, main_contract, SOLIDITY_VERSION, "byzantium", TIME_TO_FUZZ, [], MAX_TRANS_LENGTH, 2))
            mp_result.append((path, main_contract, depend_contracts, r_c, r_no_c))
            if len(mp_result) > MAX_FUZZ_FILE_SIZE:
                break
            else:
                loguru.logger.info(f"已在多进程中加入任务: {len(mp_result)} 个, 总共: {MAX_FUZZ_FILE_SIZE} 个")
        for path, main_contract, depend_contracts, r_c, r_no_c in mp_result:
            r_c = r_c.get()
            r_no_c = r_no_c.get()
            r.append(path, r_c)
            r.append(path, r_no_c)
            total_exec = r.inspect_exam(inner_out=True, csv_path="res/result.csv")
    r.remove_un_validate()
    loguru.logger.info("正在输出结果......")
    r.plot(csv_path="res/result.csv", plot_path="res/result.png")
    loguru.logger.success("完成......")
