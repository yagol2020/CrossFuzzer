"""
分析两个字节码覆盖情况之间的差异
@author: yagol
"""
import json
from typing import Dict, List


def convert_to_dict(_total_ops: list, _coverage_ops: list) -> Dict:
    situation = {}
    for op in _total_ops:
        op = int(op)
        situation[op] = 0
    for op in _coverage_ops:
        op = int(op, 16)
        situation[op] = situation[op] or 1
    return situation


def diff(_origin_dict_1: Dict, _cross_dict_2: Dict) -> List:
    situation = []
    for op in _origin_dict_1:
        if _origin_dict_1[op] == 1 and _cross_dict_2[op] == 0:
            situation.append(hex(op))
    return situation


def get_max_coverage_res_json(_candidate_files: list, _main_contract_name, _mode) -> Dict:
    max_coverage = 0
    max_coverage_file = None
    for f in _candidate_files:
        coverage = json.load(open(f))[_main_contract_name]["code_coverage"]["percentage"]
        if coverage > max_coverage:
            max_coverage = coverage
            max_coverage_file = f
    print(_mode, max_coverage, max_coverage_file)
    return json.load(open(max_coverage_file))


if __name__ == '__main__':
    ORIGIN = ['/tmp/ConFuzzius-1a4ba9eb-2966-4b0a-9015-5ec38871143e.json', "/tmp/ConFuzzius-042ac220-1270-43ba-96c0-0bd3aab75bed.json", "/tmp/ConFuzzius-8f26ebbe-bc2d-4598-9f3f-505e003bb1db.json", "/tmp/ConFuzzius-08e91408-8fad-4714-8e67-b6c3f9a79832.json", "/tmp/ConFuzzius-42c7ca57-a691-43a5-8a3c-335abf6c0014.json"]
    CROSS = [
        # '/tmp/ConFuzzius-09c99276-6dd0-4e7f-afd1-22c51e634622.json',
        '/tmp/ConFuzzius-ebfcafde-807d-4fa9-a0af-f55adb2debd1.json',
        # "/tmp/ConFuzzius-84125b11-23b3-4131-8d25-a28b503ce544.json",
        # "/tmp/ConFuzzius-0b489a8e-70ec-4366-8e57-3fce41315ae6.json",
        # "/tmp/ConFuzzius-3129bb9b-dcb4-4ac9-835f-f9391986b719.json"
    ]
    MAIN_CONTRACT = "Pass1"
    json_origin = get_max_coverage_res_json(ORIGIN, MAIN_CONTRACT, "origin")
    json_cross = get_max_coverage_res_json(CROSS, MAIN_CONTRACT, "cross")
    dict_origin = convert_to_dict(json_origin[MAIN_CONTRACT]['total_op'], json_origin[MAIN_CONTRACT]['coverage_op'])
    dict_cross = convert_to_dict(json_cross[MAIN_CONTRACT]['total_op'], json_cross[MAIN_CONTRACT]['coverage_op'])
    diff_res = diff(dict_origin, dict_cross)
    print(diff_res)
