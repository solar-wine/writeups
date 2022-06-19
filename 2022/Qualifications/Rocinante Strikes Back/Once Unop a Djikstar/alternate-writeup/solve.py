import csv
import pathlib
import numpy as np
from scipy.sparse.csgraph import dijkstra


BASEPATH = pathlib.Path(__file__).parent.resolve()


def parse_csv(out, path, reverse=False):
    def get_target_traversal_cost(name):
        weight_for_type = {
            0: 2.718,
            1: 3.141,
            2: 4.04,
            3: 1999.9,
        }
        last_char = name[-1]
        if last_char in "0123456789":
            return weight_for_type[int(last_char) % 3]
        return weight_for_type[3]

    def add(out, source, dest, r):
        if source not in out:
            out[source] = {}
        out[source][dest] = float(r) * get_target_traversal_cost(dest)

    with open(path, "r") as f:
        reader = csv.reader(f)
        lines = list(reader)[1:]

    for line in lines:
        if reverse:
            add(out, line[1], line[0], line[2])
        else:
            add(out, line[0], line[1], line[2])

    return out


def find_path(src, dst, pred):
    path = [dst]
    current_node = dst
    while current_node != src:
        current_node = pred[current_node]
        if current_node < 0:
            raise Exception("No path found")
        path.append(current_node)
    return path[::-1]


def solve():
    # Build the graph of distances
    distances = {}
    parse_csv(distances, BASEPATH / "challenge" / "users.csv")
    parse_csv(distances, BASEPATH / "challenge" / "sats.csv")
    parse_csv(distances, BASEPATH / "challenge" / "gateways.csv", reverse=True)

    # We want to convert the graph to a matrix so scipy can use it
    # First, build the list of all nodes
    nodes = []
    for k in distances:
        nodes.append(k)
        nodes += list(distances[k].keys())
    nodes = sorted(list(dict.fromkeys(nodes)))

    # Then, assign each node to an index
    nodes_map = {nodes[i]: i for i in range(len(nodes))}

    # Now, build the matrix itself
    d = np.zeros((len(nodes), len(nodes)))
    for src in nodes:
        i = nodes_map[src]

        # Some nodes may have no path leaving from them (e.g. Honolulu)
        if src not in distances:
            continue

        for dst in distances[src]:
            j = nodes_map[dst]
            d[i, j] = distances[src][dst]

    # Ask scipy to run the Dijkstra algorithm for us
    # We only care about paths starting from ShippyMcShipFace, and given paths
    # are considered directed (i.e. having a path from node A to node B does not
    # mean there is a path from node B to node A)
    _, predecessors = dijkstra(
        csgraph=d,
        directed=True,
        indices=nodes_map["ShippyMcShipFace"],
        return_predecessors=True,
    )

    # Now, get the best path from the result
    path = find_path(
        nodes_map["ShippyMcShipFace"],
        nodes_map["Honolulu"],
        predecessors,
    )

    # Convert back from each node index to the node name before returning
    return [nodes[i] for i in path]


if __name__ == "__main__":
    print(solve())
