"""
临时写的小程序

"""
import json
from typing import List


def dot_test():
    import pydot
    import os
    dot_str = os.popen("surya graph ~/Dataset/E.sol").read()
    os.popen("surya graph ~/Dataset/E.sol | dot -Tpng > ~/Dataset/E.png").read()
    dot = pydot.graph_from_dot_data(dot_str)
    print(dot)


def json_test():
    lines = open("/home/yy/Dataset/mainnet/contracts.json").readlines()

    for line in lines:
        j = json.loads(line)
        print(j)


json_test()
