import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.gridspec as gridspec
from matplotlib.colors import to_rgba

# --- 1. 数据准备 (数值完全保留，未做任何变动) ---

data = {
    'Curve': [
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
    ],
    'Algorithm': [
        'KeyGen', 'KeyGen', 'KeyGen', 'KeyGen', 'KeyGen', 'KeyGen',
        'Sign', 'Sign', 'Sign', 'Sign', 'Sign', 'Sign',
        'AS.SignAuth', 'AS.SignAuth', 'AS.SignAuth', 'AS.SignAuth', 'AS.SignAuth', 'AS.SignAuth',
        'Verify', 'Verify', 'Verify', 'Verify', 'Verify', 'Verify',
        'AS.VerAuth', 'AS.VerAuth', 'AS.VerAuth', 'AS.VerAuth', 'AS.VerAuth', 'AS.VerAuth',
    ],
    'Scheme': [
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
    ],
    'Time': [
        # 1. KeyGen
        6.608, 7.279, 15.659, 15.931, 31.496, 32.185,
        # 2. Sign
        0.651, 0.797, 1.287, 1.562, 2.894, 2.622,
        # 3. AS.SignAuth
        np.nan, 4.209, np.nan, 11.825, np.nan, 29.563,
        # 4. Verify
        0.124, 0.146, 0.181, 0.163, 0.279, 0.303,
        # 5. AS.VerAuth
        np.nan, 0.717, np.nan, 1.12, np.nan, 1.78,
    ]
}

df = pd.DataFrame(data)

# --- 2. 设置全局字体 ---
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['axes.unicode_minus'] = False

# --- 3. 颜色与绘图顺序 ---
blue = to_rgba((169 / 255, 224 / 255, 247 / 255), alpha=1)
orange = to_rgba((252 / 255, 210 / 255, 138 / 255), alpha=1)
palette = [blue, orange]
plot_order = ['KeyGen', 'Sign', 'AS.SignAuth', 'Verify', 'AS.VerAuth']

# --- 4. 布局设置 ---
fig = plt.figure(figsize=(30, 18))
gs = fig.add_gridspec(2, 6)
ax1 = fig.add_subplot(gs[0, 0:2])
ax2 = fig.add_subplot(gs[0, 2:4])
ax3 = fig.add_subplot(gs[0, 4:6])
ax4 = fig.add_subplot(gs[1, 1:3])
ax5 = fig.add_subplot(gs[1, 3:5])

axes = [ax1, ax2, ax3, ax4, ax5]
labels = ['(a)', '(b)', '(c)', '(d)', '(e)']

# --- 5. 循环绘图 ---
for i, algorithm in enumerate(plot_order):
    ax = axes[i]
    subset_df = df[df['Algorithm'] == algorithm]

    sns.barplot(
        data=subset_df,
        x="Curve",
        y="Time",
        hue="Scheme",
        palette=palette,
        width=0.92,
        ax=ax
    )

    # --- 修改点：根据算法动态设置 Y 轴标题 ---
    ax.set_xlabel("Elliptic Curves", fontsize=28)
    if algorithm in ["AS.SignAuth", "AS.VerAuth"]:
        ax.set_ylabel("Execution Time (seconds)", fontsize=30)
    else:
        ax.set_ylabel("Execution Time (milliseconds)", fontsize=30)

    ax.tick_params(axis='both', which='major', labelsize=26)

    # 数值标注
    for p in ax.patches:
        height = p.get_height()
        if pd.notna(height) and height > 0:
            annotation_format = format(height, '.3f')
            ax.annotate(annotation_format,
                        (p.get_x() + p.get_width() / 2., height),
                        ha='center', va='center',
                        xytext=(0, 15),
                        textcoords='offset points',
                        fontsize=26)

    ax.patch.set_edgecolor('black')
    ax.patch.set_linewidth(1.5)
    ax.patch.set_linestyle('--')

    # --- 调整 Y 轴范围以适配不变量的数据值 ---
    if algorithm == "KeyGen":
        ax.set_ylim(0, 40)
    elif algorithm == "Sign":
        ax.set_ylim(0, 3.5)
    elif algorithm == "AS.SignAuth":
        ax.set_ylim(0, 35)  # 适配 29.563
    elif algorithm == "Verify":
        ax.set_ylim(0, 0.4)
    elif algorithm == "AS.VerAuth":
        ax.set_ylim(0, 2.2)  # 适配 1.78

    # 图例处理
    if i == 0:
        legend = ax.legend(loc='upper left', fontsize=22, frameon=True)
        plt.setp(legend.get_title(), fontsize=22)
    else:
        if ax.get_legend() is not None:
            ax.get_legend().remove()

    # 子图标签
    ax.text(0.5, -0.22, f"{labels[i]} Algorithm: {algorithm}", fontsize=30, weight='bold', ha='center', va='center',
            transform=ax.transAxes)

# --- 6. 最终显示 ---
plt.tight_layout(rect=[0, 0.05, 1, 1], h_pad=5.0, w_pad=3.0)
plt.savefig("computation_final.png", dpi=300, bbox_inches='tight')
plt.show()