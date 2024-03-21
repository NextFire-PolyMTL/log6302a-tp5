#!/usr/bin/env python
""" Define a Graph with nodes, edges, root and extra node related information """
from code_analysis.GraphException import GraphException
from graphviz import Source
import json

try:
    shell = get_ipython().__class__.__name__
    if shell == 'ZMQInteractiveShell':
        is_notebook = True
        from PIL import Image
        from IPython.display import display
    else:
        is_notebook = False
except NameError:
    is_notebook = False

class Graph:
    def __init__(self):
        self.__filename = None
        self.__rootId = None
        self.__predTable = {}
        self.__succTable = {}
        self.__nodeTypeTable = {}
        self.__nodeImageTable = {}
        self.__nodePositionTable = {}
        self.__varIdTable = {}
        self.__varScopeTable = {}

    def get_node_ids(self) -> list:
        return list(self.__nodeTypeTable.keys())

    def get_type(self, node_id: int) -> str:
        return self.__nodeTypeTable.get(node_id)

    def get_image(self, node_id: int) -> str:
        return self.__nodeImageTable.get(node_id)

    def get_position(self, node_id: int) -> list:
        """
        Return the position of the structure in the source file
        :rtype: object
        :param node_id: Node ID
        :return: Return a list containing : [ line begin, line end, column begin, column end, token begin, token end ]
        """
        return self.__nodePositionTable.get(node_id)

    def get_var_id(self, node_id: int) -> str:
        return self.__varIdTable.get(node_id)

    def get_var_scope(self, node_id: int) -> str:
        return self.__varScopeTable.get(node_id)

    def get_children(self, node_id: int) -> list:
        if node_id in self.__succTable:
            return self.__succTable.get(node_id)
        return []

    def get_parents(self, node_id: int) -> list:
        if node_id in self.__predTable:
            return self.__predTable.get(node_id)
        return []

    def get_root(self) -> int:
        return self.__rootId

    def set_root(self, node_id: int):
        self.__rootId = node_id

    def get_filename(self) -> str:
        return self.__filename

    def set_filename(self, name: str):
        self.__filename = name

    @staticmethod
    def add_edge_table(node1: int, node2: int, table: dict):
        if node2 in table.keys():
            if node1 in table[node2]:
                raise GraphException(f"Duplicate edge : {node2} - {node1}")
        else:
            table[node2] = []
        table[node2].append(node1)

    def add_edge(self, parent_node: int, child_node: int):
        if parent_node is None or child_node is None:
            raise GraphException(f"Undefined edge.")
        self.add_edge_table(child_node, parent_node, self.__succTable)
        self.add_edge_table(parent_node, child_node, self.__predTable)

    def remove_edge(self, parent_node: int, child_node: int):
        if parent_node is None or child_node is None:
            raise GraphException(f"Undefined edge.")
        if parent_node not in self.__succTable.keys():
            return
        if child_node not in self.__predTable.keys():
            return

        self.__succTable[parent_node].remove(child_node)
        self.__predTable[child_node].remove(parent_node)

    def delete_node(self, node_id: int):
        del self.__nodePositionTable[node_id]
        del self.__nodeTypeTable[node_id]
        del self.__nodeImageTable[node_id]

        if node_id in self.__succTable:
            for child_id in self.__succTable[node_id]:
                self.__predTable[child_id].remove(node_id)
        del self.__succTable[node_id]

        if node_id in self.__predTable:
            for parent_id in self.__predTable[node_id]:
                self.__succTable[parent_id].remove(node_id)
        del self.__predTable[node_id]

    def set_position(self, node_id: int, pos: list):
        self.__nodePositionTable[node_id] = pos

    def set_type(self, node_id: int, node_type: str):
        self.__nodeTypeTable[node_id] = node_type

    def set_image(self, node_id: int, node_image: str):
        self.__nodeImageTable[node_id] = node_image

    def set_var_id(self, node_id: int, var_id: str):
        self.__varIdTable[node_id] = var_id

    def set_var_scope(self, node_id: int, var_scope: str):
        self.__varScopeTable[node_id] = var_scope

    def dfs(self, node):
        stack = [node]
        discovered = []
        while stack:
            v = stack.pop()
            if v in discovered:
                continue
            discovered.append(v)
            for c in self.get_children(v):
                stack.append(c)
            for p in self.get_parents(v):
                stack.append(p)
        return discovered

    def to_json(self):
        out = "[\n"
        out += "  " + json.dumps(["node_root", self.get_root()]) + ",\n"
        if self.get_filename() is not None:
            out += "  " + json.dumps(["filename", self.get_filename()]) + ",\n"
        for key in self.__nodeTypeTable.keys():
            out += "  " + json.dumps(["type", key, self.get_type(key)]) + ",\n"
            if self.get_image(key) is not None:
                out += "  " + json.dumps(["image", key, self.get_image(key)]) + ",\n"
            if self.get_var_id(key) is not None:
                out += "  " + json.dumps(["var_id", key, self.get_var_id(key)]) + ",\n"
            if self.get_var_scope(key) is not None:
                out += "  " + json.dumps(["var_scope", key, self.get_var_scope(key)]) + ",\n"
            if self.get_position(key) is not None:
                if self.get_position(key)[0] is not None:
                    out += "  " + json.dumps(["line_begin", key, self.get_position(key)[0]]) + ",\n"
                if self.get_position(key)[1] is not None:
                    out += "  " + json.dumps(["line_end", key, self.get_position(key)[1]]) + ",\n"
                if self.get_position(key)[2] is not None:
                    out += "  " + json.dumps(["column_begin", key, self.get_position(key)[2]]) + ",\n"
                if self.get_position(key)[3] is not None:
                    out += "  " + json.dumps(["column_end", key, self.get_position(key)[3]]) + ",\n"
                if self.get_position(key)[4] is not None:
                    out += "  " + json.dumps(["token_begin", key, self.get_position(key)[4]]) + ",\n"
                if self.get_position(key)[5] is not None:
                    out += "  " + json.dumps(["token_end", key, self.get_position(key)[5]]) + ",\n"
            for child in self.get_children(key):
                out += "  " + json.dumps(["ast_succ", key, child]) + ",\n"

        out = out[:len(out) - 2]  # remove last comma
        out += "\n]"
        return out

    def to_dot(self):
        dot = "digraph ast {\n"
        dot += "node [shape=none];\n"

        for key in self.__nodeTypeTable.keys():
            if self.get_type(key) == "Dead" and self.get_parent(key) is None:
                continue

            image = self.get_image(key)
            if image is not None:
                if len(image) >= 40:
                    image = image[:40 - 3] + "..."
                image = image.replace("\"", "'")
                image = image.replace("\\", "")
                image = image.replace("/", "")
                image = image.replace("&", "&amp;")
                image = image.replace("<", "&lt;")
                image = image.replace(">", "&gt;")
                image = image.replace("\r", "")
                image = image.replace("\n", " ")

            cell_style = "border='0'"
            table = "<TABLE border='1' cellspacing='0' cellpadding='10' style='rounded'>"
            table += f"<TR><TD {cell_style}>{key}</TD>"
            table += f"<TD {cell_style}><B>{self.get_type(key)}</B></TD></TR>"
            if image is not None:
                if self.get_var_id(key) is not None:
                    table += f"<HR/><TR><TD {cell_style}>({self.get_var_scope(key)}, {self.get_var_id(key)})</TD><TD {cell_style}>{image}</TD></TR>"
                else:
                    table += f"<HR/><TR><TD {cell_style} colspan='2'>{image}</TD></TR>"
            table += "</TABLE>"

            dot += f"{key} [label=<{table}>];\n"
            if self.get_children(key) is not None:
                for child in self.get_children(key):
                    dot += f"{key} -> {child} [weight=10];\n"

        dot += "}\n"
        return dot

    def show(self, filename="graph.dot", format="png"):
        dot = self.to_dot()
        s = Source(dot, filename=filename, format=format)
        s.render()
        if is_notebook:
            img = Image.open(filename+"."+format)
            display(img)
            return
        #s.view(cleanup=True)
