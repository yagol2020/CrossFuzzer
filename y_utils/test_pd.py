"""
pandas学习
@author: yagol
"""
import random

import pandas as pd


class PandasData:
    def __init__(self):
        self.a = random.choice(["Tom", "Jerry"])
        self.b = random.choice(["Boy", "Girl"])
        self.c = random.randint(1, 10)


df = pd.DataFrame([PandasData().__dict__ for i in range(5)])
print(df)
print("=====================================")
# group by a and b, and count mean of c
print(df.groupby(["a", "b"])["c"].mean().reset_index())
