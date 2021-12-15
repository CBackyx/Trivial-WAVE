import numpy as np
from pylab import rcParams
import seaborn as sns
import matplotlib.pyplot as plt

from matplotlib import rcParams
import matplotlib as mpl
mpl.rcParams.update({'font.size': 14})
mpl.rcParams['pdf.fonttype'] = 42
mpl.rcParams['ps.fonttype'] = 42

# sns.set_style("white")
style_label = "default"

green = "mediumseagreen"
red = "salmon"
blue = "steelblue"

# def bar_figure1(ax):
#     y_pos = [0.38, 1.56, 1.80, 2.14, 2.48]
#     n_groups = [1, 4, 8, 16, 32]
#     index = np.arange(len(n_groups))
#     width = 0.4
#     ax.bar(index, y_pos, width, align='center', color="lightblue") #'#B9E0A5'
#     # ax.set_yticks(y_pos)
#     ax.set_xticks(index)
#     ax.set_xticklabels(n_groups)
#     # ax.set_xlabel('Performance')
#     ax.set_title('Dispatch delay of different patch number', pad=10)
#     ax.set_ylim(ymin=0, ymax=3)
#     ax.set_xlabel("(a)") 

delays = [
0.18878984451293945,
0.26850342750549316,
0.36997461318969727,
0.4756007194519043,
0.5902180671691895,
0.6906719207763672,
0.7731904983520508,
0.8306384086608887,
0.9258213043212891,
1.0846068859100342]
delays1=[0.11013293266296387,0.14963912963867188,0.19490766525268555,0.21288299560546875,0.25368380546569824,0.2986786365509033,0.35734081268310547,0.4072456359863281,0.43262290954589844,0.46564459800720215]

# num: 1 ti: 103
# num: 5 ti: 117
# num: 9 ti: 131
# num: 13 ti: 137
# num: 17 ti: 145
# num: 21 ti: 151
# num: 25 ti: 154
# num: 29 ti: 159
# num: 33 ti: 162
# num: 37 ti: 167
# num: 41 ti: 170
# num: 45 ti: 173
# num: 49 ti: 175
# num: 53 ti: 178
# num: 57 ti: 179
# num: 61 ti: 181

def line_figure1(ax):
    global delays, delays1
    # delays = np.array([103,117,131,137,145,151,154,159,162,167,170,173,175,178,179,181,184])
    # delays = delays / 100
    n_groups = [1, 5, 9, 33, 65]
    index = [x+1 for x in range(10)]
    ax.plot(index, delays, marker='d', markersize=4 , color='steelblue')
    ax.plot(index, delays1, marker='*', markersize=4 , color='red')
    
    # ax.set_yticks(y_pos)
    ax.set_xticks(range(0,11,1))
    ax.set_xticklabels(range(0,11,1), fontsize=14)
    # ax.set_xticklabels(0,173,175,178,179,181,184])
    ax.set_xlabel('Num of Certificate in Authorization Chain')
    # ax.set_title('Dispatch delay of different patch number', pad=10)
    ax.set_ylim(ymin=0, ymax=2)
    # ax.set_xlabel("(a) Dispatch delay of various patch numbers") 
    ax.xaxis.labelpad = 8
    ax.legend(('Prove','Verify' ),
        loc='upper left', ncol=1)



    

# def stacked_figure3(ax):
#     N = 5
#     Triggering = [3.9] * N
#     Dispatching = [0.5] * N
#     Executing = [1.7, 1.6, 2.0, 1.5, 4.4]
#     ind = np.arange(N)    # the x locations for the groups
#     width = 0.35       # the width of the bars: can also be len(x) sequence

#     B1 = [0] * N
#     B2 = [0] * N
#     for i in range(N):
#         B1[i] = Triggering[i]
#         B2[i] = B1[i] + Dispatching[i]

#     p1 = ax.bar(ind, Triggering, width, color= green) #'#B9E0A5'
#     p2 = ax.bar(ind, Dispatching, width, bottom=B1, color=red) #'#F19C99'
#     p3 = ax.bar(ind, Executing, width, bottom=B2, color=blue) #'#A9C4EB'

#     # ax.set_ylabel('Scores')
#     ax.set_title('Total patch delay for different CVEs')
#     ax.set_xticks(ind)
#     ax.set_xticklabels(['C1', 'C2', 'C4', 'C5', 'C6'])
#     ax.set_yticks(np.arange(0, 14, 2))
#     ax.legend(('Triggering', 'Dispatching', 'Executing'),
#         loc='upper left', mode='expand', ncol=3)




def draw_figure():
    (fig_width, fig_height) = plt.rcParams['figure.figsize']
    fig_size = [fig_width, fig_height / 1.7]
    fig, axes = plt.subplots(ncols=1, nrows=1, num=style_label,
                             figsize=fig_size, squeeze=True)
    axes.set_ylabel("Delay [s]")
    # axes[1].set_ylabel("Total Patch Delay (μs)")
    line_figure1(axes)
    plt.subplots_adjust(left=0.13, bottom=0.24, right=0.95, top=0.94, wspace=0.23)
    plt.show()
    fig.savefig("chain_perf.pdf")

draw_figure()