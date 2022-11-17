"""
Cross Fuzz Contract 实验分析

@author: yagol
"""
from cross_contract_fuzz_setting import *
import os
import numpy as np
import pandas as pd

logger = get_logger()
RESULT_PATHS = []
for root, dirs, files in os.walk("res"):
    for file in files:
        if file.endswith("csv"):  # 定位文件夹下, 所有的csv结尾的文件
            RESULT_PATHS.append(os.path.join(root, file))


class RQ1:
    """
    RQ1: 与其他SOTA相比, cross_fuzzer的代码覆盖率和漏洞数量如何?
    """

    def __init__(self, _res_df: pd.DataFrame):
        self.base_dir = "RQ1"
        self.res_df = _res_df
        # self.plot_coverage()
        self.locate_one_coverage()

    def plot_coverage(self):
        """
        画出代码覆盖率的图
        :return:
        """

        class EachFile:
            def __init__(self, _mode, _loc_level, _coverage, _bug_num):
                self.mode = _mode
                self.loc_level = _loc_level
                self.coverage = _coverage
                self.bug_num = _bug_num

        import matplotlib as mpl
        import matplotlib.pyplot as plt
        import seaborn as sns
        mpl.rcParams[u'font.sans-serif'] = ['simhei']
        mpl.rcParams['axes.unicode_minus'] = False
        datas = []
        for path, path_df in self.res_df.groupby("path"):
            loc = len(open(str(path)).readlines())
            if loc < 200:
                loc_level = "<200"
            elif loc <= 500:
                loc_level = "<500"
            elif loc <= 1000:
                loc_level = "<1k"
            else:
                loc_level = ">=1k"
            for mode, mode_df in path_df.groupby("mode"):
                coverage_mean = mode_df["coverage"].mean()
                bug_num_mean = mode_df["find_bug_count"].mean()
                datas.append(EachFile(mode, loc_level, coverage_mean, bug_num_mean))
        datas = pd.DataFrame([vars(data) for data in datas])
        # 将结果保存到csv文件中
        datas.to_csv(os.path.join(self.base_dir, "RQ1_coverage.csv"), index=False)
        # 柱状图-覆盖率
        mean_df = datas.groupby(["mode", "loc_level"]).mean().reset_index()
        mean_df.to_csv(os.path.join(self.base_dir, "RQ1_coverage_mean.csv"), index=False)
        sns.barplot(x="loc_level", y="coverage", hue="mode", data=mean_df, errorbar=None,
                    hue_order=["cross", "confuzzius"],
                    order=["<200", "<500", "<1k", ">=1k"]
                    )
        plt.xlabel("合约规模")
        plt.ylabel("字节码覆盖率")
        plt.legend(title="模式")
        plt.tight_layout()
        plt.savefig(os.path.join(self.base_dir, "RQ1_coverage_bar.png"), dpi=500)
        # 柱装图-漏洞数量
        mean_df = datas.groupby(["mode", "loc_level"]).mean().reset_index()
        mean_df.to_csv(os.path.join(self.base_dir, "RQ1_bug_num_mean.csv"), index=False)
        sns.barplot(x="loc_level", y="bug_num", hue="mode", data=mean_df, errorbar=None,
                    hue_order=["cross", "confuzzius"],
                    order=["<200", "<500", "<1k", ">=1k"]
                    )
        plt.xlabel("合约规模")
        plt.ylabel("漏洞数量")
        plt.legend(title="模式")
        plt.tight_layout()
        plt.savefig(os.path.join(self.base_dir, "RQ1_bug_num_bar.png"), dpi=500)

    def locate_one_coverage(self):
        class TimeCoverage:
            def __init__(self, _time, _coverage, _tool):
                self.time = _time
                self.coverage = _coverage
                self.tool = _tool

        import matplotlib as mpl
        import matplotlib.pyplot as plt
        import seaborn as sns
        mpl.rcParams[u'font.sans-serif'] = ['simhei']
        mpl.rcParams['axes.unicode_minus'] = False
        # 找到cross和confuzzius相差的最大的合约, 同时保存transaction的信息
        paths_df = self.res_df.groupby(["path", "mode"]).mean().reset_index()
        for path, g_df in paths_df.groupby("path"):
            # 计算覆盖率的差值
            cross_coverage = g_df[g_df["mode"] == "cross"]["coverage"].values[0]
            confuzzius_coverage = g_df[g_df["mode"] == "confuzzius"]["coverage"].values[0]
            coverage_diff = cross_coverage - confuzzius_coverage
            # 填写进df
            g_df["coverage_diff"] = coverage_diff
            paths_df.loc[g_df.index, "coverage_diff"] = coverage_diff
        # 保存到csv文件中
        paths_df.to_csv(os.path.join(self.base_dir, "RQ1_coverage_diff.csv"), index=False)
        # 去两个模式里分别运行, 结果在log/res_close.json 和log/res_open.json中
        cross_json = json.load(open("log/res_open.json"))["District0xNetworkToken"]["generations"]
        confuzzius_json = json.load(open("log/res_close.json"))["District0xNetworkToken"]["generations"]
        max_time_threshold = 600
        # 每0.5秒统计一次覆盖率
        coverage = {"cross": {}, "confuzzius": {}}
        for i in np.arange(0.5, max_time_threshold + 1, 0.5):
            for data in cross_json.copy():
                if data["time"] <= i:
                    temp_list = coverage["cross"].get(i, [])
                    temp_list.append(data["code_coverage"])
                    coverage["cross"][i] = temp_list
                    cross_json.remove(data)
            for data in confuzzius_json.copy():
                if data["time"] <= i:
                    temp_list = coverage["confuzzius"].get(i, [])
                    temp_list.append(data["code_coverage"])
                    coverage["confuzzius"][i] = temp_list
                    confuzzius_json.remove(data)
        # 计算每秒的平均覆盖率
        for mode, mode_coverage in coverage.items():
            for time, time_coverage in mode_coverage.items():
                mode_coverage[time] = sum(time_coverage) / len(time_coverage)
        # 补全缺失的时间
        for mode, mode_coverage in coverage.items():
            for i in np.arange(0.5, max_time_threshold + 1, 0.5):
                if i not in mode_coverage:
                    mode_coverage[i] = mode_coverage[i - 0.5]
        # 转换到TimeCoverage
        datas = []
        for mode, mode_coverage in coverage.items():
            for time, time_coverage in mode_coverage.items():
                datas.append(TimeCoverage(time, time_coverage, mode))
        coverage_df = pd.DataFrame([data.__dict__ for data in datas])
        coverage_df.to_csv(os.path.join(self.base_dir, "RQ1_coverage_time.csv"), index=False)
        # 画图
        sns.lineplot(data=coverage_df, x="time", y="coverage", hue="tool")
        plt.xlabel("时间/s")
        plt.ylabel("覆盖率")
        plt.legend(title="模式")
        plt.tight_layout()
        plt.savefig(os.path.join(self.base_dir, "RQ1_coverage_time.png"), dpi=500)


class RQ2:
    def __init__(self, _res_df: pd.DataFrame):
        self.res_df = _res_df


if __name__ == "__main__":
    res_df = pd.concat([pd.read_csv(path) for path in RESULT_PATHS]).drop_duplicates()
    rq1 = RQ1(res_df)
    rq2 = RQ2(res_df)
