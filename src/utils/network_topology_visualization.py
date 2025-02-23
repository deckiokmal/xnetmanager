import networkx as nx
import matplotlib.pyplot as plt

class NetworkTopologyVisualizer:
    def __init__(self):
        self.graph = nx.Graph()

    def add_device(self, device_id, device_name):
        self.graph.add_node(device_id, name=device_name)

    def add_connection(self, device_id_1, device_id_2):
        self.graph.add_edge(device_id_1, device_id_2)

    def visualize(self):
        pos = nx.spring_layout(self.graph)
        labels = nx.get_node_attributes(self.graph, 'name')
        nx.draw(self.graph, pos, with_labels=True, labels=labels, node_size=2000, node_color='lightblue', font_size=10, font_weight='bold')
        plt.show()
