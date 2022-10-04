"""
静态分析获得跨合约事务序列
@author: yagol

"""
import os
import random
import subprocess
from enum import Enum
import uuid

import matplotlib.pyplot as plt
import networkx as nx
import pydot
from slither import Slither
from slither.core.expressions import CallExpression, Identifier
from slither.core.solidity_types import UserDefinedType
from slither.core.variables.state_variable import StateVariable

from fuzzer.utils import settings

visited = set()
trans_seq = [[], [], [], [], [], [], [], [], [], [], [], [], [], []]
cache = []  # 该文件的所有函数, 所对应的跨合约序列
init = False  # 表示是否初始化完成, 若完成则为True


def check_cross_init():
    return init


def get_trans_from_cache():
    """
    随机获得一个函数的跨合约序列
    """
    return random.choice(cache)


class MyType(Enum):
    FUNCTION = 1
    STATE_VARIABLE = 2


class MyEdgeType(Enum):
    INNER_INVOKE = 1
    CROSS_INVOKE = 2
    SV_READ = 3
    SV_WRITE = 4


class MyNode:
    def __init__(self, _contract, _name, _type: MyType, _sl_contract=None, _sl_function=None):
        self.contract = _contract
        self.name = _name
        self.type: MyType = _type
        self.sl_contract = _sl_contract
        self.function = _sl_function

    def validation(self):
        if self.type == MyType.FUNCTION:
            if self.sl_contract is None or self.function is None:
                raise Exception("信息不全")

    def __str__(self):
        return f"{self.contract}.{self.name}({self.type})"

    def desc(self):
        return self.__str__()


def clean():
    global visited, trans_seq
    visited = set()
    trans_seq = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]


def cross_cfg_test(sol_path):
    # 首先，处理好每个合约内部的数据流, 至于函数调用控制流, 交给SURYA处理
    SOLC_PATH = settings.SOLC_PATH_CROSS
    SURYA = settings.SURYA_PATH_CROSS
    cmd = f"{SURYA} graph {sol_path}"
    output = subprocess.check_output(cmd, shell=True)
    dot = pydot.graph_from_dot_data(output.decode('utf-8'))
    assert len(dot) == 1
    dot = dot[0]
    # dot.write_png(f"DOT.png")
    sl = Slither(sol_path, solc=SOLC_PATH)

    for contract in sl.contracts:
        for sub_graph in dot.get_subgraph_list():
            if sub_graph.get_name() == "\"cluster" + contract.name + "\"":
                for st in contract.state_variables:
                    node = pydot.Node(f"{contract.name}.{st.name}", shape="box", label=st.name)  # 状态变量
                    sub_graph.add_node(node)
                for f in contract.functions:
                    if f.is_constructor_variables:
                        continue
                    f_name = f"\"{contract.name}.{f.name}\""
                    if f.is_constructor:
                        f_name = f"\"{contract.name}.<Constructor>\""
                    for st_w in f.state_variables_written:
                        edge = pydot.Edge(f_name, f"{contract.name}.{st_w.name}", color="red")
                        sub_graph.add_edge(edge)
                    for st_r in f.state_variables_read:
                        edge = pydot.Edge(f"{contract.name}.{st_r.name}", f_name, color="blue")
                        sub_graph.add_edge(edge)
                break
    # dot to png
    # dot.write_png(f"DOT_SV.png")
    # print(f"dot file: /tmp/{uuid_str}.dot")
    g = nx.DiGraph()
    all_function_node = []
    for node in dot.get_node_list():
        if "." not in node.get_name() or len(node.get_name().replace("\"", "").split(".")) != 2:
            continue
        ctc, func = node.get_name().replace("\"", "").split(".")
        if func == "<Constructor>":
            continue
        sl_contract = sl.get_contract_from_name(ctc)
        if len(sl_contract) != 1:
            continue
        sl_contract = sl_contract[0]
        sl_func = None
        for f in sl_contract.functions:
            if f.name == func:
                sl_func = f
        func_node = MyNode(ctc, func, MyType.FUNCTION, _sl_contract=sl_contract, _sl_function=sl_func)
        all_function_node.append(func_node)
        g.add_node(func_node.desc(), content=func_node)
    for sub_graph in dot.get_subgraph_list():
        if sub_graph.get_name().startswith("cluster_"):
            continue
        for node in sub_graph.get_node_list():
            if "." not in node.get_name() or len(node.get_name().replace("\"", "").split(".")) != 2:
                continue
            ctc, func = node.get_name().replace("\"", "").split(".")
            if func == "<Constructor>":
                continue
            sl_contract = sl.get_contract_from_name(ctc)
            if len(sl_contract) != 1:
                continue
            sl_contract = sl_contract[0]
            sl_func = None
            for f in sl_contract.functions:
                if f.name == func:
                    sl_func = f
            if "shape" in node.get_attributes() and node.get_attributes()["shape"] == "box":
                var_node = MyNode(ctc, func, MyType.STATE_VARIABLE)
                g.add_node(var_node.desc(), content=var_node)
            else:
                func_node = MyNode(ctc, func, MyType.FUNCTION, sl_contract, sl_func)
                all_function_node.append(func_node)
                g.add_node(func_node.desc(), content=func_node)
    for edge in dot.get_edge_list():
        source = edge.get_source().replace("\"", "")
        if "Fallback" in source:
            continue
        dest = edge.get_destination().replace("\"", "")
        if "Fallback" in dest:
            continue
        if "<Constructor>" in source or "<Constructor>" in dest:
            continue
        color = edge.get_attributes()["color"].replace("\"", "")
        if color == "orange":  # 外部调用, 两个都是函数
            external_state = None
            source = source + f"({MyType.FUNCTION})"
            dest = dest + f"({MyType.FUNCTION})"
            source_node = g.nodes[source]["content"].function
            if source_node is None:
                continue
            for external_call_exp in source_node.external_calls_as_expressions:
                if isinstance(external_call_exp, CallExpression):
                    if hasattr(external_call_exp.called, "expression"):
                        if isinstance(external_call_exp.called.expression, Identifier) and isinstance(external_call_exp.called.expression.value, StateVariable) and isinstance(external_call_exp.called.expression.value.type, UserDefinedType) and external_call_exp.called.expression.value.type.type.name == dest.split(".")[0]:
                            external_state = external_call_exp.called.expression.value.name
            if external_state is not None:
                g.add_edge(source, dest, label=MyEdgeType.CROSS_INVOKE, external_state_var=g.nodes[source]['content'].sl_contract.name + "." + external_state + f"({MyType.STATE_VARIABLE})")
            else:
                g.add_edge(source, dest, label=MyEdgeType.CROSS_INVOKE, external_state_var="Parameter_YAGOL")
        elif color == "red":  # 状态变量写入, source是函数, dest是状态变量
            source = source + f"({MyType.FUNCTION})"
            dest = dest + f"({MyType.STATE_VARIABLE})"
            g.add_edge(source, dest, label=MyEdgeType.SV_WRITE)
        elif color == "blue":  # 状态变量读取, source是状态变量, dest是函数
            source = source + f"({MyType.STATE_VARIABLE})"
            dest = dest + f"({MyType.FUNCTION})"
            g.add_edge(source, dest, label=MyEdgeType.SV_READ)
        elif color == "green":  # 内部函数调用, 两个都是函数
            source = source + f"({MyType.FUNCTION})"
            dest = dest + f"({MyType.FUNCTION})"
            g.add_edge(source, dest, label=MyEdgeType.INNER_INVOKE)
    for sub_graph in dot.get_subgraph_list():
        if sub_graph.get_name().startswith("cluster_"):
            continue
        for edge in sub_graph.get_edge_list():
            source = edge.get_source().replace("\"", "")
            dest = edge.get_destination().replace("\"", "")
            if "<Constructor>" in source or "<Constructor>" in dest:
                continue
            color = edge.get_attributes()["color"].replace("\"", "")
            if color == "orange":  # 外部调用, 两个都是函数
                source = source + f"({MyType.FUNCTION})"
                dest = dest + f"({MyType.FUNCTION})"
                source_node = g.nodes[source]["content"].function
                g.add_edge(source, dest, label=MyEdgeType.CROSS_INVOKE)  # 添加依赖的状态变量, 如果有的话
            elif color == "red":  # 状态变量写入, source是函数, dest是状态变量
                source = source + f"({MyType.FUNCTION})"
                dest = dest + f"({MyType.STATE_VARIABLE})"
                g.add_edge(source, dest, label=MyEdgeType.SV_WRITE)
            elif color == "blue":  # 状态变量读取, source是状态变量, dest是函数
                source = source + f"({MyType.STATE_VARIABLE})"
                dest = dest + f"({MyType.FUNCTION})"
                g.add_edge(source, dest, label=MyEdgeType.SV_READ)
            elif color == "green":  # 内部函数调用, 两个都是函数
                source = source + f"({MyType.FUNCTION})"
                dest = dest + f"({MyType.FUNCTION})"
                g.add_edge(source, dest, label=MyEdgeType.INNER_INVOKE)
    # plot g to png(dot)
    # nx.nx_pydot.write_dot(g, "test.dot")
    all_function_node = set([node.desc() for node in all_function_node])
    for node_choose in all_function_node:
        if "Fallback" in node_choose:
            continue
        clean()
        deep(_node=node_choose, _g=g, _index=1)
        for trans in trans_seq.copy():
            if len(trans) == 0:
                trans_seq.remove(trans)
        trans_seq.reverse()
        random_trans = []
        for index, trans in enumerate(trans_seq):
            trans_r = trans.copy()
            random.shuffle(trans_r)
            random_trans.extend(trans_r)
        random_trans.append(node_choose)
        # 处理一下，弄成confuzzius能接收的形式, 似乎surya对参数列表不敏感
        ret = []
        for tran in random_trans:
            temp = tran.replace("(" + str(MyType.FUNCTION) + ")", "")
            c_name, f_sign = temp.split(".")
            if f_sign == "fallback":
                continue
            c_sl = sl.get_contract_from_name(c_name)[0]
            skip = False
            seek = False
            for f_seek in c_sl.functions:
                if f_seek.name == f_sign:
                    seek = True  # 必须是函数
                    if f_seek.visibility == "internal" or f_seek.visibility == "private":
                        skip = True  # 如果是internal，跳过
                        break
                    else:
                        break
            if not skip and seek:
                ret.append((c_name, f_sign))
        if len(ret) == 0:
            continue
        global cache, init
        cache.append((node_choose, ret))
    init = True


def deep(_node, _g, _index, _select=False, _predecessor=None):
    if _node == "Parameter_YAGOL":  # 他来自与参数，不是状态变量，无需寻找他的setter
        return
    if _predecessor is None:
        _predecessor = []
    _l = f"{_node}"
    if _l in visited:
        return
    visited.add(_l)
    neighbors = _g.predecessors(_node)
    for neighbor in neighbors:
        edge_info = _g.get_edge_data(neighbor, _node)['label']
        if edge_info == MyEdgeType.INNER_INVOKE:
            if _select:
                trans_seq[_index].append(neighbor)
            deep(_node=neighbor, _g=_g, _index=_index)
        elif edge_info == MyEdgeType.SV_READ:  # 当前应该是函数
            if neighbor in _predecessor:
                continue
            deep(_node=neighbor, _g=_g, _index=_index + 1)
        elif edge_info == MyEdgeType.SV_WRITE:  # 按理说，当前应该是状态变量
            trans_seq[_index].append(neighbor)
            _predecessor.append(_node)
            deep(_node=neighbor, _g=_g, _index=_index, _select=True, _predecessor=_predecessor)
    successors = _g.successors(_node)
    for successor in successors:
        edge_info = _g.get_edge_data(_node, successor)['label']
        if edge_info == MyEdgeType.CROSS_INVOKE:
            cross_depend_contract = _g.get_edge_data(_node, successor)['external_state_var']
            deep(_node=cross_depend_contract, _g=_g, _index=_index)
            deep(_node=successor, _g=_g, _index=_index)

# settings.SOLC_PATH_CROSS = "/home/yy/anaconda3/envs/ConFuzzius/bin/solc"
# settings.SURYA_PATH_CROSS = "/usr/local/bin/surya"
# # -s /tmp/ConFuzzius-d65a7d0e-6ab8-471f-91c8-46a2be2de544.sol -c DappleAirdrops
# cross_cfg_test("/home/yy/ConFuzzius-Cross/examples/T.sol")
# for f, trans in cache:
#     print(f, "==>\t\t\t", trans)
