import os
from datetime import datetime
from cross_contract_fuzz_setting import *
import subprocess
from slither import Slither
import pandas as pd

logger = get_logger()


def check_compile(file_path: str):
    try:
        Slither(file_path, solc=SOLC)
    except Exception as e:
        logger.error(f"Compile error: {file_path}, {str(e).split()[0:1]}")
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
        logger.error(f"Surya error: {file_path}, {str(e).split()[0:1]}")
        return False
    return True


class FileCache:
    def __init__(self, _path, _contract_name, _loc, _fuzzable):
        self.path = _path
        self.contract_name = _contract_name
        self.loc = _loc
        self.fuzzable = _fuzzable
        self.create_time = datetime.now().strftime("%Y/%m/%d/%H:%M:%S")


if __name__ == '__main__':
    count = 0
    if not os.path.exists("file_cache.csv"):
        df = pd.DataFrame(columns=["path"])
    else:
        df = pd.read_csv("file_cache.csv")
    for root, dirs, files in os.walk(LARGE_SCALE_DATASETS):
        for file in files:
            path = os.path.join(root, file)
            if path.endswith(".sol") \
                    and path not in df["path"].values \
                    and len(os.path.basename(path).replace(".sol", "").split("_")) == 2 \
                    and len(os.path.basename(path).replace(".sol", "").split("_")[0]) == 40:
                contract_name = os.path.basename(path).replace(".sol", "").split("_")[1]
                loc = len(open(path).readlines())
                fuzzable = False
                if check_compile(path) and check_surya(path):
                    fuzzable = True
                    logger.success(f"Compile and surya success: {path}")
                file_cache = FileCache(path, contract_name, loc, fuzzable)
                df = pd.concat([df, pd.DataFrame([file_cache.__dict__])])
                count += 1
                if count == 50:
                    df.to_csv("file_cache.csv", index=False)
                    count = 0
                    logger.info(f"Save file cache: {path}")
