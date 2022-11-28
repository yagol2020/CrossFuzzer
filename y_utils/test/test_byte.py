from y_utils.solc_compiler import get_pcs, compile

compiler_output = compile("0.4.26", "byzantium", "/home/yy/ConFuzzius-Cross/y_utils/test/Example.sol")

bin_bytecode = compiler_output["contracts"]["/home/yy/ConFuzzius-Cross/y_utils/test/Example.sol"]["EtherBank"]["evm"]["deployedBytecode"]["object"]
total_bbs = get_pcs(bin_bytecode)
for i in total_bbs:
    print(i)
print("======")
confuzzius_json = eval(open("confuzzius.json").read())
len_bb = len(confuzzius_json["total_op"])
assert len_bb == len(total_bbs), "confuzzius和solc编译出来的字节码长度不一致"
print(len_bb)
assert confuzzius_json["code_coverage"]["percentage"] == len(confuzzius_json["coverage_op"]) / len_bb * 100, "confuzzius覆盖率计算错误"

xfuzz_json = eval(open("xfuzz.json").read())
xfuzz_bbs = xfuzz_json["cov_infos_ya"]
print(len(xfuzz_bbs))
print(len(xfuzz_bbs) / len_bb)
print("======")
real_bb_set = set(total_bbs)
xfuzz_bb_set = set([int(i) for i in xfuzz_bbs.keys()])
xfuzz_cov = real_bb_set & xfuzz_bb_set
print(len(xfuzz_cov))
print(len(xfuzz_cov) / len(total_bbs))
