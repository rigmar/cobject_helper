import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import pygraphviz
from networkx.drawing.nx_agraph import *

def get_label_size(label):
    line_len = 0
    for line in label.split("\n"):
        if line_len < len(line):
            line_len = len(line)
    return line_len*500

G = nx.DiGraph()

G.add_node("ROOT")

for i in xrange(5):
    G.add_node("Child_%i" % i)
    G.add_node("Grandchild_%i" % i)
    G.add_node("Greatgrandchild_%i" % i)

    G.add_edge("ROOT", "Child_%i" % i)
    G.add_edge("Child_%i" % i, "Grandchild_%i" % i)
    G.add_edge("Grandchild_%i" % i, "Greatgrandchild_%i" % i)

# write dot file to use with graphviz
# run "dot -Tpng test.dot >test.png"
#nx.write_dot(G,'test.dot')
print(list(G.nodes()))
sizes = []
for node in list(G.nodes()):
    sizes.append(get_label_size(node))
# same layout using matplotlib with no labels

pos=graphviz_layout(G,prog='dot')
#nx.draw(G,pos, node_shape = "s")
plt.savefig('nx_test.png')
#plt.show()
print(list(G.edges()))
for u,v,d in G.edges(data=True):
    print u
    print v
    print d
    d['label'] = "aaabbb"
A = to_agraph(G)
A.layout('dot')
A.draw('test.png')
image = mpimg.imread('test.png')
plt.axis("off")
plt.imshow(image)
plt.show()