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
import pandas as pd
from slither.core.expressions import TypeConversion, Identifier, AssignmentOperation

from slither.core.solidity_types import UserDefinedType
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.state_variable import StateVariable

loguru.logger.add("log/DEBUG.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="DEBUG")
loguru.logger.add("log/INFO.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="INFO")
loguru.logger.add("log/ERROR.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="ERROR")
loguru.logger.add("log/WARNING.log", encoding="utf-8", enqueue=True, backtrace=True, diagnose=True, level="WARNING")

SOLC = "/home/yy/anaconda3/envs/ConFuzzius/bin/solc"  # 用于slither分析
FUZZER = "fuzzer/main.py"  # docker内的main.py
PYTHON = "python3"  # docker内的python3
MAIN_NET_INFO_PATH = "/home/yy/Dataset/mainnet/contracts.json"  # 用于获得每个合约的trans数量
DOCKER_IMAGES_NAME = "confuzzius"  # docker镜像的名字
MAX_FUZZ_FILE_SIZE = 100  # 一轮实验里, fuzz多少个文件?
TIME_TO_FUZZ = 10 * 60  # 单位: 秒

THRESHOLD = 5  # 事务数量超过这个值, 才会被选中

MAX_PROCESS_NUM = 16  # 最大多进程数量, 应该小于CPU核心数量

MAX_TRANS_LENGTH = 10  # fuzz过程中, 生成的最大事务序列长度
REPEAT_NUM = 3  # 重复次数
SOLIDITY_VERSION = "v0.4.26"

loguru.logger.info(f"任务数量: {MAX_FUZZ_FILE_SIZE}, Fuzz时间: {TIME_TO_FUZZ}秒")
loguru.logger.info(f"预计最低执行时间: {MAX_FUZZ_FILE_SIZE * 2 * TIME_TO_FUZZ * REPEAT_NUM / MAX_PROCESS_NUM / 60}分钟, 即{MAX_FUZZ_FILE_SIZE * 2 * TIME_TO_FUZZ * REPEAT_NUM / MAX_PROCESS_NUM / 60 / 60}小时")
time.sleep(1)  # 休息几秒钟, 查看任务设置

mainnet_info = {}

cache_fuzz_able_contracts = []

FUZZ_ABLE_CACHE_PATH = "cache/fuzzable_cache.csv"

fuzz_cache_df = pd.read_csv(FUZZ_ABLE_CACHE_PATH)


def save_df():
    global fuzz_cache_df
    fuzz_cache_df.to_csv(FUZZ_ABLE_CACHE_PATH, index=False)


def read_in_fuzz_able_paths_from_cache_df():
    global fuzz_cache_df
    # remove duplicate
    fuzz_cache_df = fuzz_cache_df.drop_duplicates()
    # save fuzz_cache_df
    save_df()
    # load path into cache_fuzz_able_contracts, only if enable is True
    global cache_fuzz_able_contracts
    cache_fuzz_able_contracts = list(fuzz_cache_df[fuzz_cache_df["enable"] != 0]["path"])
    random.shuffle(cache_fuzz_able_contracts)
    loguru.logger.success(f"成功从缓存中读取{len(cache_fuzz_able_contracts)}个可fuzz合约")


read_in_fuzz_able_paths_from_cache_df()


def cache_mainnet_info():
    """
    缓存mainnet的信息
    """
    loguru.logger.info("开始缓存mainnet的信息")
    lines = open(MAIN_NET_INFO_PATH).readlines()
    for line in lines:
        j = json.loads(line)
        address = j["address"]
        trans_count = j["txcount"]
        mainnet_info[address] = trans_count
    loguru.logger.success("成功缓存main net事务数据......")


cache_mainnet_info()


def cache_fuzz_able_contracts_to_df(_path, _main_contract_name, _solc_version, _trans_count):
    global fuzz_cache_df
    fuzz_cache_df = pd.concat([fuzz_cache_df, pd.DataFrame({
        "path": [_path],
        "main_contract_name": [_main_contract_name],
        "solc_version": [_solc_version],
        "trans_count": [_trans_count]
    })], ignore_index=True)
    save_df()


def load_ethereum_mainnet_info(_query_address) -> bool:
    """
    用于判断这个文件, 事务数量是否超过指定值
    """

    trans_count = mainnet_info.get(_query_address, -1)
    if trans_count > THRESHOLD:
        loguru.logger.info(f"该合约的事务数量为: {trans_count} > {THRESHOLD}, 符合条件")
        return True
    else:
        loguru.logger.warning(f"该合约不符合事务数量阈值, 跳过")
        return False


@loguru.logger.catch()
def load_dataset(dir_path: str, debug_mode: bool = False) -> Tuple[str, str, list, list]:
    if debug_mode:
        BE_TEST_PATH = "/home/yy/ConFuzzius-Cross/examples/T.sol"
        BE_TEST_CONTRACT_NAME = "T"
        _debug_depend_contracts, _debug_sl = analysis_depend_contract(file_path=BE_TEST_PATH, _contract_name=BE_TEST_CONTRACT_NAME)
        _debug_constructor_args = analysis_main_contract_constructor(file_path=BE_TEST_PATH, _contract_name=BE_TEST_CONTRACT_NAME, sl=_debug_sl)
        yield BE_TEST_PATH, BE_TEST_CONTRACT_NAME, _debug_depend_contracts, _debug_constructor_args
    else:
        paths = []  # 所有sol文件的路径, 用于打乱, 否则总是那么几个文件
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".sol"):
                    p = os.path.join(root, file)
                    paths.append(p)
        random.shuffle(paths)
        # 暂时不启动paths, 用缓存的数据直接测试, 加快效率
        global cache_fuzz_able_contracts
        paths = cache_fuzz_able_contracts
        for p in paths:
            if len(os.path.basename(p).replace(".sol", "").split("_")) != 2:
                continue
            # if p != "/home/yy/Dataset/mainnet/9a/9afa7e446e5393e50277af6baefa92b2bdf66850_GAME.sol":
            #     continue
            address = "0x" + os.path.basename(p).replace(".sol", "").split("_")[0]
            contract_name = os.path.basename(p).replace(".sol", "").split("_")[1]
            assert len(address) == 42, "地址的长度为2 + 40"
            if load_ethereum_mainnet_info(_query_address=address) and check_compile(p) and check_surya(p):
                _depend_contracts, _sl = analysis_depend_contract(file_path=p, _contract_name=contract_name)
                _constructor_args = analysis_main_contract_constructor(file_path=p, _contract_name=contract_name, sl=_sl)
                if _constructor_args is None:
                    loguru.logger.warning("分析构造函数出现错误, 跳过......")
                    continue
                cache_fuzz_able_contracts_to_df(_path=p, _main_contract_name=contract_name, _solc_version=SOLIDITY_VERSION, _trans_count=mainnet_info.get(address, -1))
                if len(_depend_contracts) == 0:
                    # update cache
                    fuzz_cache_df.loc[fuzz_cache_df["path"] == p, "enable"] = 0
                    fuzz_cache_df.loc[fuzz_cache_df["path"] == p, "remark"] = "没有依赖的合约"
                    save_df()
                    loguru.logger.debug(f"跳过非跨合约文件: {p}, 已更新缓存")
                    continue  # 跳过非跨合约的文件, 这类文件没有比较的意义了
                if "mainnet" in p:
                    yield p, contract_name, _depend_contracts, _constructor_args


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


def analysis_depend_contract(file_path: str, _contract_name: str) -> Tuple:
    """
    不是文件内所有的合约, 都需要部署一次
    1. 主合约继承的合约, 如果没有被[参数]/[状态变量]所调用或依赖, 那么不用部署
    2. 注意这一步需要进一步分析主合约继承的合约

    :param file_path: 文件路径
    :param _contract_name: 主合约名字
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
    return list(res), sl


def analysis_main_contract_constructor(file_path: str, _contract_name: str, sl: Slither = None):
    if sl is None:
        sl = Slither(file_path, solc=SOLC)
    contract = sl.get_contract_from_name(_contract_name)
    assert len(contract) == 1, "理论上, 根据合约名字, 只能找到一个合约"
    contract = contract[0]
    # 1. 分析合约内的构造函数
    constructor = contract.constructor
    if constructor is None:  # 没有构造函数
        return []
    # 1. 获得构造函数的所有参数, 若name不为address, 则为其设置YA_DO_NOT_KNOW, 其他的暂时初始化为一个list, list保存数据流
    res = []
    for p in constructor.parameters:
        if hasattr(p.type, "name"):
            if p.type.name != "address":
                res.append((p.name, p.type.name, "YA_DO_NOT_KNOW", ["YA_DO_NOT_KNOW"]))
            else:
                res.append((p.name, p.type.name, [p.name], []))
        else:  # 可能是数组
            return None
    # 2. 分析构造函数内部数据流流动
    for exps in constructor.expressions:  # 解析构造函数内部的表达式, 分析哪些数据流向了状态变量
        if isinstance(exps, AssignmentOperation):
            exps_right = exps.expression_right
            exps_left = exps.expression_left
            if isinstance(exps_right, Identifier) and isinstance(exps_left, Identifier):
                for cst_param in res:
                    if isinstance(cst_param[2], list) and exps_right.value.name in cst_param[2]:
                        cst_param[2].append(exps_left.value.name)
            elif isinstance(exps_right, TypeConversion) and isinstance(exps_left, Identifier):
                param_name, param_map_contract_name = extract_param_contract_map(exps_right)
                if param_name is not None and param_map_contract_name is not None:
                    for cst_param in res:
                        if isinstance(cst_param[2], list) and param_name in cst_param[2]:
                            cst_param[3].append(param_map_contract_name)
        elif isinstance(exps, TypeConversion):
            param_name, param_map_contract_name = extract_param_contract_map(exps)
            if param_name is not None and param_map_contract_name is not None:
                for cst_param in res:
                    if isinstance(cst_param[2], list) and param_name in cst_param[2]:
                        cst_param[3].append(param_map_contract_name)
    # 转换res
    ret = []
    for p_name, p_type, _, p_value in res:
        if p_type == "address" and len(p_value) == 0:
            p_value = ["YA_DO_NOT_KNOW"]
        p_value = list(set(p_value))
        assert len(p_value) == 1, "理论上, 每个参数只能有一个预期值"
        ret.append(f"{p_name} {p_type} {p_value[0]}")
    loguru.logger.debug("构造函数参数为: " + str(ret))
    return ret


def extract_param_contract_map(exps: TypeConversion):
    inner_exp = exps.expression
    if isinstance(inner_exp, Identifier) \
            and isinstance(exps.type, UserDefinedType) \
            and hasattr(exps.type, "type") \
            and isinstance(exps.type.type, Contract):
        return inner_exp.value.name, exps.type.type.name
    else:
        return None, None


class FuzzerResult:
    """
    单一fuzz结果
    """

    def __init__(self, _path, _contract_name, _coverage, _detect_result, _mode: int, _depend_contract_num: int, _total_op, _coverage_op):
        self.path = _path
        self.contract_name = _contract_name
        self.coverage = _coverage
        self.detect_result = _detect_result
        self.mode = _mode  # 跨合约是否开启? 1开启, 2未开启
        self.depend_contract_num = _depend_contract_num  # 依赖合约数量
        self.total_op = _total_op  # 总共的操作码
        self.coverage_op = _coverage_op  # 覆盖的操作码


class Result:
    def __init__(self):
        self.res = {}  # type:Dict[str, List[FuzzerResult]]

    def append(self, _path, _fuzzer_results: list):
        for _fuzzer_result in _fuzzer_results:
            if _fuzzer_result is None:  # 当fuzz处理失败时, 会出现None, 这里过滤这种情况
                return
            temp_list = self.res.get(_path, [])
            temp_list.append(_fuzzer_result)
            self.res[_path] = temp_list
            assert len(self.res[_path]) <= 2 * REPEAT_NUM

    def remove_un_validate(self):
        """
        验证是否存在2个mode的结果, 如果不存在, 警告并删除
        """
        for p, rs in self.res.copy().items():
            if len(rs) != 2 * REPEAT_NUM:
                loguru.logger.warning(f"存在不合法的结果, 该地址有{len(rs)}个结果, {p}")
                self.res.pop(p)

    def inspect_exam(self, csv_path, op_summary_csv_path) -> int:
        """
        实验过程中检测
        返回当前Result里已有多少合法结果
        """
        self.remove_un_validate()
        loguru.logger.success("中间检查: 已经过滤不合法的结果, 剩余结果数量: " + str(len(self.res)))
        self.save_result(csv_path=csv_path, op_summary_csv_path=op_summary_csv_path)
        return len(self.res)

    def save_result(self, csv_path, op_summary_csv_path):
        """
        保存fuzz结果
        """
        self.remove_un_validate()
        if len(self.res) == 0:
            loguru.logger.warning("没有结果可供绘图")
            return
        cov = []

        class Coverage:
            def __init__(self, _path, _mode, _coverage, _find_bug_count, _depend_contract_num):
                self.path = _path
                self.mode = "cross" if _mode == 1 else "single"
                self.coverage = _coverage
                self.find_bug_count = _find_bug_count
                self.depend_contract_num = _depend_contract_num
                self.record_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 展开结果, 将结果平铺
        for p, rs in self.res.items():
            for ro in rs:
                cov.append(Coverage(p, ro.mode, ro.coverage, len(ro.detect_result), ro.depend_contract_num))
        result_df = pd.DataFrame([c.__dict__ for c in cov])
        result_df.sort_values(by="coverage", inplace=True)
        if csv_path is not None:
            result_df.to_csv(csv_path, index=False)
        # 第二部分, 统计两个模式整体的覆盖情况, 对操作码的覆盖情况进行或运算
        cov = []
        for p, rs in self.res.items():
            cross_cov = {}
            single_cov = {}
            # 先初始化所有的操作码, 覆盖情况为0
            temp_ro = rs[0]
            for op in temp_ro.total_op:
                cross_cov[op] = 0
                single_cov[op] = 0
            # 然后进行或运算
            for ro in rs:
                if ro.mode == 1:
                    for op in ro.coverage_op:
                        op = int(op, 16)
                        cross_cov[op] = cross_cov[op] or 1
                else:
                    for op in ro.coverage_op:
                        op = int(op, 16)
                        single_cov[op] = single_cov[op] or 1
            # 计算覆盖率
            cross_cov = sum(cross_cov.values()) / len(cross_cov) * 100
            single_cov = sum(single_cov.values()) / len(single_cov) * 100
            cov.append(Coverage(p, 1, cross_cov, 0, 0))
            cov.append(Coverage(p, 2, single_cov, 0, 0))
        result_df = pd.DataFrame([c.__dict__ for c in cov])
        result_df.sort_values(by="coverage", inplace=True)
        if op_summary_csv_path is not None:
            result_df.to_csv(op_summary_csv_path, index=False)


def run_fuzzer(_file_path: str, _main_contract, solc_version: str, evm_version: str, timeout: int, _depend_contracts: list, max_individual_length: int, _cross_contract: int, _constructor_args: list, _fuzz_index: int, _seed):
    import uuid
    uuid = uuid.uuid4()
    res_path = f"/tmp/ConFuzzius-{uuid}.json"
    file_path = f"/tmp/ConFuzzius-{uuid}.sol"
    shutil.copyfile(_file_path, file_path)  # 移动到/tmp里, 这个是和docker的共享目录
    loguru.logger.info(f"UUID为{uuid}")
    if _cross_contract == 1:
        depend_contracts_str = " ".join(_depend_contracts)
        constructor_str = " ".join(_constructor_args)
        cmd = f"{PYTHON} {FUZZER} -s {file_path} -c {_main_contract} --seed {_seed} --solc {solc_version} --evm {evm_version} -t {timeout} --cross-contract {_cross_contract} --depend-contracts {depend_contracts_str} --constructor-args {constructor_str} --constraint-solving 0 --result {res_path} --max-individual-length {max_individual_length} --solc-path-cross /usr/local/bin/solc --surya-path-cross /usr/local/bin/surya"
        run_in_docker(cmd, _images="cross", _contract_name=_main_contract, _fuzz_index=_fuzz_index)
    else:
        cmd = f"{PYTHON} {FUZZER} -s {file_path} -c {_main_contract} --seed {_seed} --solc {solc_version} --evm {evm_version} -t {timeout} --constraint-solving 0 --result {res_path} --max-individual-length {max_individual_length}"
        run_in_docker(cmd, _images="origin", _contract_name=_main_contract, _fuzz_index=_fuzz_index)
    time.sleep(1)
    if os.path.exists(res_path):
        res = json.load(open(res_path))[_main_contract]
        code_coverage = res["code_coverage"]["percentage"]
        detect_result = res["errors"]
        total_op = res["total_op"]
        coverage_op = res["coverage_op"]
        return FuzzerResult(file_path, _main_contract, code_coverage, detect_result, _cross_contract, len(_depend_contracts), _total_op=total_op, _coverage_op=coverage_op)
    else:
        loguru.logger.warning(f"执行命令: {cmd}, 模式为 {_cross_contract} 时, 未能生成结果文件, 请检查")
        return None


def run_in_docker(cmd: str, _images: str, _contract_name: str, _fuzz_index: int):
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
    timestamp_str = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    r = Result()
    mp_result = []
    with multiprocessing.Pool(processes=MAX_PROCESS_NUM) as pool:
        for path, main_contract, depend_contracts, constructor_args in load_dataset("/home/yy/Dataset"):
            loguru.logger.info(f"正在处理{path}")
            repeat_r_cross = []
            repeat_r_single = []
            for i in range(REPEAT_NUM):
                seed = random.random()
                r_c = pool.apply_async(run_fuzzer, args=(path, main_contract, SOLIDITY_VERSION, "byzantium", TIME_TO_FUZZ, depend_contracts, MAX_TRANS_LENGTH, 1, constructor_args, i, seed))
                r_no_c = pool.apply_async(run_fuzzer, args=(path, main_contract, SOLIDITY_VERSION, "byzantium", TIME_TO_FUZZ, [], MAX_TRANS_LENGTH, 2, constructor_args, i, seed))
                repeat_r_cross.append(r_c)
                repeat_r_single.append(r_no_c)
            mp_result.append((path, main_contract, depend_contracts, repeat_r_cross, repeat_r_single))
            if len(mp_result) > MAX_FUZZ_FILE_SIZE:
                break
            else:
                loguru.logger.info(f"已在多进程中加入任务: {len(mp_result)} 个, 总共: {MAX_FUZZ_FILE_SIZE} 个")
        for path, main_contract, depend_contracts, r_c_s, r_no_c_s in mp_result:
            assert len(r_c_s) == len(r_no_c_s)
            r_c_s_res = [r_c.get() for r_c in r_c_s]
            r_no_c_s_res = [r_no_c.get() for r_no_c in r_no_c_s]
            r.append(path, r_c_s_res)
            r.append(path, r_no_c_s_res)
            total_exec = r.inspect_exam(csv_path=f"res/result_{timestamp_str}.csv", op_summary_csv_path=f"res/op_summary_{timestamp_str}.csv")
    r.remove_un_validate()
    loguru.logger.info("正在输出结果......")
    r.save_result(csv_path=f"res/result_{timestamp_str}.csv", op_summary_csv_path=f"res/op_summary_{timestamp_str}.csv")
    loguru.logger.success("完成......")
