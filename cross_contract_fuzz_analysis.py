"""
Cross Fuzz Contract 实验分析

@author: yagol
"""
from cross_contract_fuzz_setting import *
import os

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
        self.plot_coverage()

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
        plt.show()
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
        plt.show()


if __name__ == "__main__":
    res_df = pd.concat([pd.read_csv(path) for path in RESULT_PATHS]).drop_duplicates()
    rq1 = RQ1(res_df)
