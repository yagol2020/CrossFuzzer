"""
@author: yagol
"""
import os
import slither
import pandas as pd
import json

from cache import check_surya

SOLC_PATH = "/home/yy/anaconda3/envs/cross_fuzz/bin/solc"
SB_CURATE_DIR = '/home/yy/Dataset/SBCurate'
BUG_INFO = json.load(open(os.path.join(SB_CURATE_DIR, 'vulnerabilities.json')))


class SBContract:
    def __init__(self, _path, _contract_name):
        self.path = _path
        self.contract_name = _contract_name
        self.bug_type = ""
        self.bug_line = []
        self.handle()

    def handle(self):
        for bug in BUG_INFO:
            if bug["path"].replace("dataset", "") in self.path:
                self.bug_type = bug["vulnerabilities"][0]['category']
                for v in bug["vulnerabilities"]:
                    self.bug_line.extend(v['lines'])
                break


if __name__ == "__main__":
    df = pd.DataFrame()
    for root, dirs, files in os.walk(SB_CURATE_DIR):
        for f in files:
            if f.endswith('.sol'):
                f_path = os.path.join(root, f)
                try:
                    sl = slither.Slither(f_path, solc=SOLC_PATH)
                    if not check_surya(f_path):
                        continue
                    if len(sl.contracts) > 1:
                        for c in sl.contracts:
                            if "Log" in c.name or "LOG" in c.name or "ERC20" in c.name or "attach" in c.name or "SafeMath" in c.name or "Ownable" in c.name:
                                continue
                            if c.name.upper() == os.path.basename(f_path).replace(".sol", "").upper():
                                sb = SBContract(f_path, c.name)
                                df = pd.concat([df, pd.DataFrame([sb.__dict__])])
                                break
                            sb = SBContract(f_path, c.name)
                            df = pd.concat([df, pd.DataFrame([sb.__dict__])])
                except Exception as e:
                    print(f"{f_path} compile error")
    df.to_csv("sb_curate.csv", index=False)
