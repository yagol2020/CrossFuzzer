import seaborn
import matplotlib.pyplot as plt

# 使用seaborn绘制饼装图
seaborn.set()
plt.figure(figsize=(6, 6))
plt.pie([0.2, 0.3, 0.5], labels=['A', 'B', 'C'], autopct='%1.1f%%')
plt.show()
