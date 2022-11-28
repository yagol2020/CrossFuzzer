"""
临时写的小程序

"""
import json
import random
from enum import Enum
from typing import List, Dict

import loguru
import numpy
from pydot import Node
from slither import Slither
import networkx as nx
from slither.core.expressions import CallExpression, MemberAccess, Identifier
import matplotlib.pyplot as plt
import pydot
import os
import os
import pydot
from slither.core.variables.state_variable import StateVariable


def dot_test():
    dot_str = os.popen("surya graph ~/Dataset/E.sol").read()
    os.popen("surya graph ~/Dataset/E.sol | dot -Tpng > ~/Dataset/E.png").read()
    dot = pydot.graph_from_dot_data(dot_str)
    print(dot)


def json_test():
    lines = open("/home/yy/Dataset/mainnet/contracts.json").readlines()

    for line in lines:
        j = json.loads(line)
        print(j)


def test_docker():
    import docker
    client = docker.from_env()
    container = client.containers.run(image="confuzzius", volumes=['/tmp:/tmp'], command="python3 fuzzer/main.py -s /tmp/E.sol --solc v0.4.26 --evm byzantium -t 10 --result /tmp/123.json", detach=True)
    result = container.wait()
    print(result)
    output = container.logs()
    print(output)


def test_datatime():
    import datetime
    dt = datetime.datetime.now()
    print(dt)


def test_nx():
    G = nx.DiGraph([(1, 2), (1, 3), (2, 3), (3, 4)])
    # 判断G是否存在回环
    print(nx.is_directed_acyclic_graph(G))
    nx.draw(G, with_labels=True)
    import matplotlib.pyplot as plt
    plt.show()
    roots = (n for n, d in G.in_degree() if d == 0)
    leaves = (n for n, d in G.out_degree() if d == 0)
    res = []
    for root in roots:
        for p in nx.all_simple_paths(G, root, leaves):
            res.append(p)
    print(res)


def check_constructor():
    path_count = 0
    constructor_count = 0
    constructor_with_parma_count = 0
    for root, dirs, files in os.walk("/home/yy/Dataset"):
        for file in files:
            if file.endswith(".sol"):
                p = os.path.join(root, file)
                try:
                    slither = Slither(p, solc="/home/yy/anaconda3/envs/ConFuzzius/bin/solc")
                    print(p)
                    for contract in slither.contracts:
                        path_count += 1
                        constructor = contract.constructor
                        if constructor:
                            constructor_count += 1
                            if len(constructor.parameters) > 0:
                                constructor_with_parma_count += 1
                    print(f"{path_count}个contract里, {constructor_count}个有constructor, {constructor_with_parma_count}个有参数")

                except BaseException as be:
                    continue


check_constructor()
