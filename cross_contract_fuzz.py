"""
Cross Contract Fuzz
@author : yagol
"""
from cross_contract_fuzz_setting import *
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

import json
from slither import Slither
from slither.core.declarations import Contract
from typing import List, Dict, Tuple
import pandas as pd
from slither.core.expressions import TypeConversion, Identifier, AssignmentOperation

from slither.core.solidity_types import UserDefinedType

logger = get_logger()

logger.info(f"任务数量: {MAX_FUZZ_FILE_SIZE}, Fuzz时间: {TIME_TO_FUZZ}秒")
logger.info(f"预计最低执行时间: {MAX_FUZZ_FILE_SIZE * 2 * TIME_TO_FUZZ * REPEAT_NUM / MAX_PROCESS_NUM / 60}分钟, "
            f"即{MAX_FUZZ_FILE_SIZE * 2 * TIME_TO_FUZZ * REPEAT_NUM / MAX_PROCESS_NUM / 60 / 60}小时")
time.sleep(1)  # 休息几秒钟, 查看任务设置
fuzz_cache_df = pd.read_csv(FUZZ_ABLE_CACHE_PATH)


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
                logger.debug("通过分析合约内被写入的状态变量, 发现依赖的合约: {}".format(v.type.type.name))
        for f in contract.functions:
            # 2. 分析合约内函数的参数
            for p in f.parameters:
                if isinstance(p.type, UserDefinedType) and hasattr(p.type, "type") and isinstance(p.type.type, Contract):
                    res.add(p.type.type.name)
                    logger.debug("通过分析合约内函数的参数, 发现依赖的合约: {}".format(p.type.type.name))
            # 3. 分析函数的写入变量, 如果是合约类型, 那么也需要部署
            for v in f.variables_written:
                if hasattr(v, "type") and isinstance(v.type, UserDefinedType) and hasattr(v.type, "type") and isinstance(v.type.type, Contract):
                    res.add(v.type.type.name)
                    logger.debug("通过分析函数的写入变量(局部和状态都算), 发现依赖的合约: {}".format(v.type.type.name))
        # 3. 分析合约内的继承关系, 添加到待分析队列中
        for inherit in contract.inheritance:
            if inherit.name not in res:
                to_be_deep_analysis.put(inherit.name)
    if _contract_name in res:
        logger.debug("主合约被分析到了依赖合约中, 需要移除")
        res.remove(_contract_name)
    # 4. 判断依赖合约的bytecode, 移除为空的合约
    compilation_unit = sl.compilation_units[0].crytic_compile_compilation_unit
    for depend_c in res.copy():
        if compilation_unit.bytecode_runtime(depend_c) == "" or compilation_unit.bytecode_runtime(depend_c) == "":
            logger.debug(f"依赖合约 {depend_c}的bytecode为空, 已移除")
            res.remove(depend_c)

    logger.info("依赖合约为: " + str(res) + ", 总共有: " + str(len(sl.contracts)) + "个合约, 需要部署的合约有: " + str(len(res)) + "个")
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
    logger.debug("构造函数参数为: " + str(ret))
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

    def __init__(self, _path, _contract_name, _coverage, _detect_result, _mode: int, _depend_contract_num: int, _total_op, _coverage_op, _transaction_count, _cross_transaction_count):
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

    def append(self, _path, _fuzzer_results: list):
        for _fuzzer_result in _fuzzer_results:
            if _fuzzer_result is None:  # 当fuzz处理失败时, 会出现None, 这里过滤这种情况
                # update fuzz able cache
                fuzz_cache_df.loc[fuzz_cache_df["path"] == _path, "enable"] = 0
                fuzz_cache_df.loc[fuzz_cache_df["path"] == _path, "remark"] = "fuzz出现错误"
                fuzz_cache_df.to_csv(FUZZ_ABLE_CACHE_PATH, index=False)
                logger.debug("fuzz结果未生成, 已更新和保存缓存......")
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
                logger.warning(f"存在不合法的结果, 该地址有{len(rs)}个结果, {p}")
                self.res.pop(p)

    def inspect_exam(self, csv_path) -> int:
        """
        实验过程中检测
        返回当前Result里已有多少合法结果
        """
        self.remove_un_validate()
        logger.success("中间检查: 已经过滤不合法的结果, 剩余结果数量: " + str(len(self.res)))
        self.save_result(csv_path=csv_path)
        return len(self.res)

    def save_result(self, csv_path):
        """
        保存fuzz结果
        """
        self.remove_un_validate()
        if len(self.res) == 0:
            logger.warning("没有结果可供绘图")
            return
        cov = []

        class Coverage:
            def __init__(self, _path, _mode, _coverage, _find_bug_count, _depend_contract_num, _trans_count, _cross_trans_count):
                self.path = _path
                self.mode = "cross" if _mode == 1 else "single"
                self.coverage = _coverage
                self.find_bug_count = _find_bug_count
                self.depend_contract_num = _depend_contract_num
                self.trans_count = _trans_count
                self.cross_trans_count = _cross_trans_count
                self.record_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 展开结果, 将结果平铺
        for p, rs in self.res.items():
            for ro in rs:
                cov.append(Coverage(p, ro.mode, ro.coverage, len(ro.detect_result), ro.depend_contract_num, ro.transaction_count, ro.cross_transaction_count))
        result_df = pd.DataFrame([c.__dict__ for c in cov])
        result_df.sort_values(by="coverage", inplace=True)
        if csv_path is not None:
            result_df.to_csv(csv_path, index=False)


def run_fuzzer(_file_path: str, _main_contract, solc_version: str, evm_version: str, timeout: int, _depend_contracts: list, max_individual_length: int, _cross_contract: int, _constructor_args: list, _fuzz_index: int, _seed):
    import uuid
    uuid = uuid.uuid4()
    res_path = f"/tmp/ConFuzzius-{uuid}.json"
    file_path = f"/tmp/ConFuzzius-{uuid}.sol"
    shutil.copyfile(_file_path, file_path)  # 移动到/tmp里, 这个是和docker的共享目录
    logger.info(f"UUID为{uuid}")
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
        transaction_count = res["transactions"]["total"]
        cross_transaction_count = res.get("cross_trans_count", 0)
        return FuzzerResult(file_path, _main_contract, code_coverage, detect_result, _cross_contract, len(_depend_contracts), _total_op=total_op, _coverage_op=coverage_op, _transaction_count=transaction_count, _cross_transaction_count=cross_transaction_count)
    else:
        logger.warning(f"执行命令: {cmd}, 模式为 {_cross_contract} 时, 未能生成结果文件, 请检查")
        # update fuzz able cache
        return None


def run_in_docker(cmd: str, _images: str, _contract_name: str, _fuzz_index: int):
    """
    基于docker运行cmd
    """
    try:
        client = docker.from_env()
        container = client.containers.run(image=_images, volumes=['/tmp:/tmp'], command=cmd, detach=True)
        logger.debug(f"执行命令: {cmd}, container id: {container.id}, image: {_images}")
        result = container.wait()
        output = container.logs()
        if output is None or result is None or (result is not None and "Error" in result.items() and result["Error"] is not None):
            logger.warning(f"docker 执行命令 {cmd} 时发生错误, 错误信息: {result}")
        container.stop()
        container.remove()
    except BaseException as be:
        logger.error(f"docker运行命令: {cmd} 时出错: {be}")
        sys.exit(-1)


def load_dataset():
    pass


if __name__ == "__main__":
    timestamp_str = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    r = Result()
    mp_result = []
    with multiprocessing.Pool(processes=MAX_PROCESS_NUM) as pool:
        for path, main_contract, depend_contracts, constructor_args in load_dataset():
            logger.info(f"正在处理{path}")
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
                logger.info(f"已在多进程中加入任务: {len(mp_result)} 个, 总共: {MAX_FUZZ_FILE_SIZE} 个")
        for path, main_contract, depend_contracts, r_c_s, r_no_c_s in mp_result:
            assert len(r_c_s) == len(r_no_c_s)
            r_c_s_res = [r_c.get() for r_c in r_c_s]
            r_no_c_s_res = [r_no_c.get() for r_no_c in r_no_c_s]
            r.append(path, r_c_s_res)
            r.append(path, r_no_c_s_res)
            total_exec = r.inspect_exam(csv_path=f"res/result_{timestamp_str}.csv")
    r.remove_un_validate()
    logger.info("正在输出结果......")
    r.save_result(csv_path=f"res/result_{timestamp_str}.csv")
    logger.success("完成......")
    logger.success(f"输出的结果文件为: res/result_{timestamp_str}.csv")
