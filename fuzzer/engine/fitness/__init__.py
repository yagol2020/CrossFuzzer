#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def fitness_function(indv, env):
    """
    计算适应度, 按照论文的公式, 适应度由branch覆盖率和RAW两部分组成
    """
    block_coverage_fitness = compute_branch_coverage_fitness(env.individual_branches[indv.hash], env.code_coverage)
    if env.args.data_dependency:
        data_dependency_fitness = compute_data_dependency_fitness(indv, env.data_dependencies)
        return block_coverage_fitness + data_dependency_fitness
    return block_coverage_fitness


def compute_branch_coverage_fitness(branches, pcs):
    non_visited_branches = 0.0

    for jumpi in branches:
        for destination in branches[jumpi]:
            if not branches[jumpi][destination] and destination not in pcs:  # 如果分支没有被访问过, 并且目标地址不在pcs中
                # 这里统计的是, 测试用例没有覆盖的分支个数
                non_visited_branches += 1

    return non_visited_branches


def compute_data_dependency_fitness(indv, data_dependencies):
    data_dependency_fitness = 0.0
    all_reads = set()

    for d in data_dependencies:
        all_reads.update(data_dependencies[d]["read"])  # 将所有read的元素集合, 添加到all_reads中

    for i in indv.chromosome:
        _function_hash = i["arguments"][0]
        if _function_hash in data_dependencies:
            for i in data_dependencies[_function_hash]["write"]:
                if i in all_reads:
                    data_dependency_fitness += 1

    return data_dependency_fitness
