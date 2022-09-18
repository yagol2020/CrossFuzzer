"""
Cross Fuzz Contract 实验分析

@author: yagol
"""
import pandas as pd
import loguru

RESULT_PATH = "result.csv"

if __name__ == "__main__":
    df = pd.read_csv(RESULT_PATH)
    df = df.groupby("path")
    loss_cov_counter, loss_bug_counter = 0, 0  # cross不如single
    draw_cov_counter, draw_bug_counter = 0, 0  # cross和single一样
    win_cov_counter, win_bug_counter = 0, 0  # cross比single好
    total_counter = 0

    for path, g in df:  # 遍历group
        assert len(g) == 2, "每个path应该只有两个模式"
        total_counter += 1
        cov_cross, cov_single = 0, 0
        bug_cross, bug_single = 0, 0
        depend_contract_num_cross, depend_contract_num_single = 0, 0
        for index, row in g.iterrows():
            if row["mode"] == "cross":  # Note: 跨合约模式
                cov_cross = row["coverage"]
                bug_cross = row["find_bug_count"]
                depend_contract_num_cross = row["depend_contract_num"]
            elif row["mode"] == "single":  # 单合约模式
                cov_single = row["coverage"]
                bug_single = row["find_bug_count"]
                depend_contract_num_single = row["depend_contract_num"]
                assert depend_contract_num_single == 0  # 单合约模式下，依赖合约数应该为0
            else:
                raise ValueError("mode error")
        if cov_cross > cov_single:
            loguru.logger.success(f"{path} 覆盖率 cross > single | {cov_cross} > {cov_single}")
            win_cov_counter += 1
        elif cov_cross < cov_single:
            loguru.logger.error(f"{path} 覆盖率 cross < single | {cov_cross} < {cov_single}")
            if depend_contract_num_cross > 0:
                loguru.logger.error(f"在存在依赖合约的情况下, 覆盖率仍不如single, 依赖的合约个数为: {depend_contract_num_cross}")
            loss_cov_counter += 1
        else:
            loguru.logger.info(f"{path} 覆盖率 cross = single | {cov_cross} = {cov_single}")
            draw_cov_counter += 1
        if bug_cross > bug_single:
            loguru.logger.success(f"{path} 漏洞数 cross > single | {bug_cross} > {bug_single}")
            win_bug_counter += 1
        elif bug_cross < bug_single:
            loguru.logger.error(f"{path} 漏洞数 cross < single | {bug_cross} < {bug_single}")
            loss_bug_counter += 1
        else:
            loguru.logger.info(f"{path} 漏洞数 cross = single | {bug_cross} = {bug_single}")
            draw_bug_counter += 1
        loguru.logger.info("=======================================")
    assert total_counter == win_cov_counter + loss_cov_counter + draw_cov_counter
    assert total_counter == win_bug_counter + loss_bug_counter + draw_bug_counter
    loguru.logger.info(f"总共{total_counter}个文件")
    loguru.logger.info(f"覆盖率: win: {win_cov_counter}({win_cov_counter / total_counter * 100}%), loss: {loss_cov_counter}({loss_cov_counter / total_counter * 100}%), draw: {draw_cov_counter}({draw_cov_counter / total_counter * 100}%)")
    loguru.logger.info(f"漏洞数: win: {win_bug_counter}({win_bug_counter / total_counter * 100}%), loss: {loss_bug_counter}({loss_bug_counter / total_counter * 100}%), draw: {draw_bug_counter}({draw_bug_counter / total_counter * 100}%)")
