import os
import json

total_coverage = {}
total_stats = {}
for root, dirs, files in os.walk("./"):
    for file in files:
        path = os.path.join(root, file)
        if file.startswith("coverage_pc_"):
            total_coverage.update(json.load(open(path)))
        if file.startswith("stats_"):
            for k, v in json.load(open(path)).items():
                if k.startswith("BUG"):
                    total_stats[k] = total_stats.get(k, 0) + int(v)
json.dump(total_coverage, open("total_coverage.json", "w"))
json.dump(total_stats, open("total_stats.json", "w"))
