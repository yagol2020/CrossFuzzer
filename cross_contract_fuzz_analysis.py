"""
Cross Fuzz Contract 实验分析

@author: yagol
"""
import os

import pandas as pd
import loguru

RESULT_PATHS = []
for root, dirs, files in os.walk("res"):
    for file in files:
        if file.endswith("csv"):  # 定位文件夹下, 所有的csv结尾的文件
            RESULT_PATHS.append(os.path.join(root, file))


def plot_bar():
    pass


class RQ1:
    """
    RQ1: 与其他SOTA相比, cross_fuzzer的代码覆盖率和漏洞数量如何?
    """

    def __init__(self, _res_df: pd.DataFrame):
        self.res_df = _res_df


if __name__ == "__main__":
    # concat each result
    res_df = pd.concat([pd.read_csv(path) for path in RESULT_PATHS])
    # remove duplicated
    res_df = res_df.drop_duplicates()
    res_df = res_df.groupby("path")
    loss_cov_counter, loss_bug_counter = 0, 0  # cross不如single
    draw_cov_counter, draw_bug_counter = 0, 0  # cross和single一样
    win_cov_counter, win_bug_counter = 0, 0  # cross比single好
    total_counter = 0

    # 进一步统计
    depend_loss_cov_counter, depend_loss_bug_counter = 0, 0  # cross不如single, 即使有依赖
    depend_draw_cov_counter, depend_draw_bug_counter = 0, 0  # cross和single一样, 即使有依赖
    depend_win_cov_counter, depend_win_bug_counter = 0, 0  # cross比single好, 即使有依赖

    # 统计cross和single两个的平均覆盖率
    cross_cov, single_cov = 0, 0
    # 统计覆盖率的提升幅度
    cov_improve = []

    for path, g in res_df:  # 遍历group
        total_counter += 1
        cross_model_slice = g[g["mode"] == "cross"]
        single_model_slice = g[g["mode"] == "single"]
        cov_cross = cross_model_slice["coverage"].mean()
        cov_single = single_model_slice["coverage"].mean()
        bug_cross = cross_model_slice["find_bug_count"].mean()
        bug_single = single_model_slice["find_bug_count"].mean()
        depend_contract_num_cross = cross_model_slice["depend_contract_num"].mean()

        cross_cov += cov_cross
        single_cov += cov_single

        cov_improve.append(cov_cross - cov_single)

        if cov_cross > cov_single:
            loguru.logger.success(f"{path} 覆盖率 cross > single | {cov_cross} > {cov_single}")
            if depend_contract_num_cross > 0:
                loguru.logger.success(f"可能由于多合约的存在, 覆盖率提升, 依赖的合约个数为: {depend_contract_num_cross}")
                depend_win_cov_counter += 1
            win_cov_counter += 1
        elif cov_cross < cov_single:
            loguru.logger.error(f"{path} 覆盖率 cross < single | {cov_cross} < {cov_single}")
            if depend_contract_num_cross > 0:
                loguru.logger.error(f"在存在依赖合约的情况下, 覆盖率仍不如single, 依赖的合约个数为: {depend_contract_num_cross}")
                depend_loss_cov_counter += 1
            loss_cov_counter += 1
        else:
            draw_cov_counter += 1
        if bug_cross > bug_single:
            loguru.logger.success(f"{path} 漏洞数 cross > single | {bug_cross} > {bug_single}")
            win_bug_counter += 1
        elif bug_cross < bug_single:
            loguru.logger.error(f"{path} 漏洞数 cross < single | {bug_cross} < {bug_single}")
            loss_bug_counter += 1
        else:
            # loguru.logger.info(f"{path} 漏洞数 cross = single | {bug_cross} = {bug_single}")
            draw_bug_counter += 1
        loguru.logger.info("=======================================")
    assert total_counter == win_cov_counter + loss_cov_counter + draw_cov_counter
    assert total_counter == win_bug_counter + loss_bug_counter + draw_bug_counter
    loguru.logger.info(f"总共{total_counter}个文件")
    loguru.logger.info(f"覆盖率: win: {win_cov_counter}({win_cov_counter / total_counter * 100}%), draw: {draw_cov_counter}({draw_cov_counter / total_counter * 100}%), loss: {loss_cov_counter}({loss_cov_counter / total_counter * 100}%)")
    loguru.logger.info(f"漏洞数: win: {win_bug_counter}({win_bug_counter / total_counter * 100}%), draw: {draw_bug_counter}({draw_bug_counter / total_counter * 100}%), loss: {loss_bug_counter}({loss_bug_counter / total_counter * 100}%)")

    loguru.logger.info(f"在覆盖率win的 {win_cov_counter} 里, 有 {depend_win_cov_counter} 个是存在依赖合约的;\t在覆盖率loss的 {loss_cov_counter} 里, 有 {depend_loss_cov_counter} 个是存在依赖合约的")
    loguru.logger.info(f"cross和single的平均覆盖率: cross: {cross_cov / total_counter}, single: {single_cov / total_counter}")
