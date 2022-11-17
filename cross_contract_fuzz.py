"""
Cross Contract Fuzz
@author : yagol
"""
import binascii

from cross_contract_fuzz_setting import *
import multiprocessing
import os
import random
import shutil
import sys
import time
from datetime import datetime
from queue import Queue
import docker
import pyevmasm
import crytic_compile
import json
from slither import Slither
from slither.core.declarations import Contract
from typing import Tuple
import pandas as pd
from slither.core.expressions import TypeConversion, Identifier, AssignmentOperation
import re
from slither.core.solidity_types import UserDefinedType

logger = get_logger()

logger.info(f"任务数量: {MAX_FUZZ_FILE_SIZE}, Fuzz时间: {TIME_TO_FUZZ}秒")
logger.info(f"预计最低执行时间: {MAX_FUZZ_FILE_SIZE * len(TOOLS) * TIME_TO_FUZZ * REPEAT_NUM / MAX_PROCESS_NUM / 60}分钟, "
            f"即{MAX_FUZZ_FILE_SIZE * len(TOOLS) * TIME_TO_FUZZ * REPEAT_NUM / MAX_PROCESS_NUM / 60 / 60}小时")
logger.info("开启的工具为: " + ",".join(TOOLS))
time.sleep(5)  # 休息几秒钟, 查看任务设置
fuzz_cache_df = pd.read_csv(FUZZ_ABLE_CACHE_PATH)
label_df = pd.read_csv(SB_CURATED_LABEL_FILE)


def demo_test():
    """
    用于测试
    """
    logger.info("开始测试")
    p = "/home/yy/ConFuzzius-Cross/examples/T.sol"
    c_name = "E"
    _depend_contracts, _sl = analysis_depend_contract(file_path=p, _contract_name=c_name)
    _constructor_args = analysis_main_contract_constructor(file_path=p, _contract_name=c_name, sl=_sl)
    yield p, c_name, _depend_contracts, _constructor_args


def load_dataset():
    rows = []
    if MODE == Mode.LARGE_SCALE:
        for index, row in fuzz_cache_df.iterrows():
            if row["fuzzable"] is True and row["enable"] is not False:
                rows.append((index, row))
    elif MODE == Mode.SB_CURATED:
        for index, row in label_df.iterrows():
            rows.append((index, row))
    else:
        raise Exception
    random.shuffle(rows)
    for index, row in rows:
        p = row["path"]
        # if p != "/home/yy/Dataset/mainnet/0a/0abdace70d3790235af448c88547603b945604ea_District0xNetworkToken.sol":
        #     continue
        c_name = row["contract_name"]
        _depend_contracts, _sl = analysis_depend_contract(file_path=p, _contract_name=c_name)
        if len(_depend_contracts) <= 0:
            fuzz_cache_df.loc[index, "enable"] = False
            fuzz_cache_df.loc[index, "remark"] = "无依赖合约"
            fuzz_cache_df.to_csv(FUZZ_ABLE_CACHE_PATH, index=False)
            continue
        _constructor_args = analysis_main_contract_constructor(file_path=p, _contract_name=c_name, sl=_sl)
        if _constructor_args is None:
            fuzz_cache_df.loc[index, "enable"] = False
            fuzz_cache_df.loc[index, "remark"] = "分析构造函数失败"
            fuzz_cache_df.to_csv(FUZZ_ABLE_CACHE_PATH, index=False)
            continue
        yield p, c_name, _depend_contracts, _constructor_args


@logger.catch()
def analysis_depend_contract(file_path: str, _contract_name: str) -> Tuple[List, Slither]:
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
        if len(contract) != 1:
            logger.warning("理论上, 根据合约名字, 只能找到一个合约")
            return [], sl
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


def run_fuzzer(_file_path: str, _main_contract, solc_version: str, evm_version: str, timeout: int, _depend_contracts: list, max_individual_length: int, _cross_contract: int, _constructor_args: list, _fuzz_index: int, _seed, tool: str):
    import uuid
    uuid = uuid.uuid4()
    res_path = f"/tmp/ConFuzzius-{uuid}.json"
    file_path = f"/tmp/ConFuzzius-{uuid}.sol"
    origin_uuid_path = file_path
    shutil.copyfile(_file_path, file_path)  # 移动到/tmp里, 这个是和docker的共享目录
    logger.info(f"UUID为{uuid}")
    if _cross_contract == 1 and tool == "cross":
        depend_contracts_str = " ".join(_depend_contracts)
        constructor_str = " ".join(_constructor_args)
        cmd = f"{PYTHON} {FUZZER} -s {file_path} -c {_main_contract} --seed {_seed} --solc {solc_version} --evm {evm_version} -t {timeout} --cross-contract {_cross_contract} --depend-contracts {depend_contracts_str} --constructor-args {constructor_str} --constraint-solving 0 --result {res_path} --max-individual-length {max_individual_length} --solc-path-cross /usr/local/bin/solc --surya-path-cross /usr/local/bin/surya"
        run_in_docker(cmd, _images="cross", _fuzz_index=_fuzz_index)
        logger.debug(cmd)
    elif tool == "confuzzius":
        cmd = f"{PYTHON} {FUZZER} -s {file_path} -c {_main_contract} --seed {_seed} --solc {solc_version} --evm {evm_version} -t {timeout} --constraint-solving 0 --result {res_path} --max-individual-length {max_individual_length}"
        run_in_docker(cmd, _images="origin", _fuzz_index=_fuzz_index)
    elif tool == "sfuzz":
        # 1. 由于多进程, 因此根据uuid创建文件夹, 将合约文件放入其中
        os.mkdir(f"/tmp/{uuid}")
        shutil.copyfile(file_path, f"/tmp/{uuid}/{_main_contract}.sol")
        # 3. 修改file_path
        file_path = f"/tmp/{uuid}/{_main_contract}.sol"
        # 4. 根据我们的写法, sfuzz的输出为E.sol.json
        res_path = f"/tmp/{uuid}/{_main_contract}.cov.json"
        # 5. 生成cmd
        cmd = f"python3 auto_runner.py {file_path} {timeout}"
        # 6. 运行docker
        run_in_docker(cmd, _images="sfuzz:7.0", _fuzz_index=_fuzz_index)
        # 7. 为了避免合约名字重复, 把文件名改回来
        os.rename(file_path, f"/tmp/ConFuzzius-{uuid}.sol")
    else:
        logger.error(f"不支持的工具: {tool}, 系统退出")
        sys.exit(-1)
    time.sleep(1)
    if os.path.exists(res_path):
        if tool == "sfuzz":
            cov_bbs = json.load(open(res_path))
            bin_bytecode = crytic_compile.CryticCompile(origin_uuid_path).compilation_units[origin_uuid_path].bytecodes_runtime[_main_contract]
            if bin_bytecode.endswith("0029"):
                bin_bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bin_bytecode)
            if bin_bytecode.endswith("0033"):
                bin_bytecode = re.sub(r"5056fe.*?0033$", "5056", bin_bytecode)
            bin_bytecode = binascii.unhexlify(bin_bytecode)
            total_bbs = list(pyevmasm.disassemble_all(bin_bytecode))
            code_coverage = len(cov_bbs) / len(total_bbs) * 100
            detect_result, total_op, coverage_op, transaction_count, cross_transaction_count = {}, [], [], 0, 0
        else:
            res = json.load(open(res_path))[_main_contract]
            code_coverage = res["code_coverage"]["percentage"]
            detect_result = res["errors"]
            total_op = res["total_op"]
            coverage_op = res["coverage_op"]
            transaction_count = res["transactions"]["total"]
            cross_transaction_count = res.get("cross_trans_count", 0)
        return FuzzerResult(file_path, _main_contract, code_coverage, detect_result, _cross_contract, len(_depend_contracts), _total_op=total_op, _coverage_op=coverage_op, _transaction_count=transaction_count, _cross_transaction_count=cross_transaction_count, _tool_name=tool)
    else:
        logger.warning(f"执行命令: {cmd}, 模式为 {_cross_contract} 时, 未能生成结果文件, 请检查")
        return None


def run_in_docker(cmd: str, _images: str, _fuzz_index: int):
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


if __name__ == "__main__":
    timestamp_str = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    r = Result()
    mp_result = []
    with multiprocessing.Pool(processes=MAX_PROCESS_NUM) as pool:
        for path, main_contract, depend_contracts, constructor_args in load_dataset():
            logger.info(f"正在处理{path}")
            repeat_r = []
            for i in range(REPEAT_NUM):
                seed = random.random()
                for tool_name in TOOLS:
                    time.sleep(random.randint(1, 5))
                    if tool_name == "cross":
                        repeat_r.append(pool.apply_async(run_fuzzer, args=(path, main_contract, SOLIDITY_VERSION, "byzantium", TIME_TO_FUZZ, depend_contracts, MAX_TRANS_LENGTH, 1, constructor_args, i, seed, "cross")))
                    elif tool_name == "confuzzius":
                        repeat_r.append(pool.apply_async(run_fuzzer, args=(path, main_contract, SOLIDITY_VERSION, "byzantium", TIME_TO_FUZZ, [], MAX_TRANS_LENGTH, 2, constructor_args, i, seed, "confuzzius")))
                    elif tool_name == "sfuzz":
                        repeat_r.append(pool.apply_async(run_fuzzer, args=(path, main_contract, SOLIDITY_VERSION, "byzantium", TIME_TO_FUZZ, [], MAX_TRANS_LENGTH, 3, constructor_args, i, seed, "sfuzz")))
            mp_result.append((path, main_contract, depend_contracts, repeat_r))
            logger.info(f"已在多进程中加入任务: {len(mp_result)} 个, 总共: {MAX_FUZZ_FILE_SIZE} 个")
            if len(mp_result) >= MAX_FUZZ_FILE_SIZE:
                logger.info("已达到最大任务数, 等待多进程结果......")
                break
        for path, main_contract, depend_contracts, r_c in mp_result:
            r_c_s_res = [r_c_s.get() for r_c_s in r_c]
            r.append(path, r_c_s_res)
            total_exec = r.inspect_exam(csv_path=f"res/result_{timestamp_str}.csv")
    logger.info("正在输出结果......")
    r.save_result(csv_path=f"res/result_{timestamp_str}.csv")
    logger.success("完成......")
    logger.success(f"输出的结果文件为: res/result_{timestamp_str}.csv")
