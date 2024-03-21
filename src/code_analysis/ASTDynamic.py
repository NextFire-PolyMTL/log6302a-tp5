""" Define a ASTDynamic as a Tree with additional edge types and node information """

from code_analysis import AST
from code_analysis.GraphException import ASTDynamicException
import numpy as np

class ASTDynamic(AST):
    def __init__(self):
        super(ASTDynamic, self).__init__()

        self.__dynresPredTable = {}
        self.__dynresSuccTable = {}

        self.__dataresPredTable = {}
        self.__dataresSuccTable = {}

        self.__parsePredTable = {}
        self.__parseSuccTable = {}

        self.__evalCode = {}
        self.__evalPatterns = {}

        self.types.extend(["DecodeFailed", "VisitFailed", "ParseFailed"])

    def delete_node(self, node_id: int):
        del self.__evalCode[node_id]

        if node_id in self.__dynresSuccTable:
            for child_id in self.__dynresSuccTable[node_id]:
                self.__dynresPredTable[child_id].remove(node_id)
        del self.__dynresSuccTable[node_id]

        if node_id in self.__dynresPredTable:
            for parent_id in self.__dynresPredTable[node_id]:
                self.__dynresSuccTable[parent_id].remove(node_id)
        del self.__dynresPredTable[node_id]

        if node_id in self.__dataresSuccTable:
            for child_id in self.__dataresSuccTable[node_id]:
                self.__dataresPredTable[child_id].remove(node_id)
        del self.__dataresSuccTable[node_id]

        if node_id in self.__dataresPredTable:
            for parent_id in self.__dataresPredTable[node_id]:
                self.__dataresSuccTable[parent_id].remove(node_id)
        del self.__dataresPredTable[node_id]

        if node_id in self.__parseSuccTable:
            for child_id in self.__parseSuccTable[node_id]:
                self.__parsePredTable[child_id].remove(node_id)
        del self.__parseSuccTable[node_id]

        if node_id in self.__parsePredTable:
            for parent_id in self.__parsePredTable[node_id]:
                self.__parseSuccTable[parent_id].remove(node_id)
        del self.__parsePredTable[node_id]

        super(ASTDynamic, self).delete_node(node_id)


    def add_dynres_edge(self, parent_node: int, child_node: int):
        if parent_node is None or child_node is None:
            raise ASTDynamicException(f"Undefined dynres edge.")
        self.add_edge_table(child_node, parent_node, self.__dynresSuccTable)
        self.add_edge_table(parent_node, child_node, self.__dynresPredTable)

    def remove_dynres_edge(self, parent_node: int, child_node: int):
        if parent_node is None or child_node is None:
            raise ASTDynamicException(f"Undefined dynres edge.")
        if parent_node not in self.__dynresSuccTable.keys():
            return
        if child_node not in self.__dynresPredTable.keys():
            return

        self.__dynresSuccTable[parent_node].remove(child_node)
        self.__dynresPredTable[child_node].remove(parent_node)

    def add_datares_edge(self, parent_node: int, child_node: int):
        if parent_node is None or child_node is None:
            raise ASTDynamicException(f"Undefined datares edge.")
        self.add_edge_table(child_node, parent_node, self.__dataresSuccTable)
        self.add_edge_table(parent_node, child_node, self.__dataresPredTable)

    def remove_datares_edge(self, parent_node: int, child_node: int):
        if parent_node is None or child_node is None:
            raise ASTDynamicException(f"Undefined datares edge.")
        if parent_node not in self.__dataresSuccTable.keys():
            return
        if child_node not in self.__dataresPredTable.keys():
            return

        self.__dataresSuccTable[parent_node].remove(child_node)
        self.__dataresPredTable[child_node].remove(parent_node)

    def add_parse_edge(self, parent_node: int, child_node: int):
        if parent_node is None or child_node is None:
            raise ASTDynamicException(f"Undefined parse edge.")
        self.add_edge_table(child_node, parent_node, self.__parseSuccTable)
        self.add_edge_table(parent_node, child_node, self.__parsePredTable)

    def remove_parse_edge(self, parent_node: int, child_node: int):
        if parent_node is None or child_node is None:
            raise ASTDynamicException(f"Undefined parse edge.")
        if parent_node not in self.__parseSuccTable.keys():
            return
        if child_node not in self.__parsePredTable.keys():
            return

        self.__parseSuccTable[parent_node].remove(child_node)
        self.__parsePredTable[child_node].remove(parent_node)


    def get_dynres_children(self, node_id: int) -> list:
        if node_id in self.__dynresSuccTable:
            return self.__dynresSuccTable.get(node_id)
        return []

    def get_dynres_parents(self, node_id: int) -> list:
        if node_id in self.__dynresPredTable:
            return self.__dynresPredTable.get(node_id)
        return []

    def get_datares_children(self, node_id: int) -> list:
        if node_id in self.__dataresSuccTable:
            return self.__dataresSuccTable.get(node_id)
        return []

    def get_datares_parents(self, node_id: int) -> list:
        if node_id in self.__dataresPredTable:
            return self.__dataresPredTable.get(node_id)
        return []

    def get_parse_children(self, node_id: int) -> list:
        if node_id in self.__parseSuccTable:
            return self.__parseSuccTable.get(node_id)
        return []

    def get_parse_parents(self, node_id: int) -> list:
        if node_id in self.__parsePredTable:
            return self.__parsePredTable.get(node_id)
        return []

    def get_any_children(self, node_id: int) -> list:
        children = self.get_children(node_id).copy()
        children.extend(self.get_dynres_children(node_id))
        children.extend(self.get_datares_children(node_id))
        children.extend(self.get_parse_children(node_id))
        return children

    def get_any_parents(self, node_id: int) -> list:
        children = self.get_parents(node_id).copy()
        children.extend(self.get_dynres_parents(node_id))
        children.extend(self.get_datares_parents(node_id))
        children.extend(self.get_parse_parents(node_id))
        return children

    def set_eval_code(self, node_id: int, code: str):
        self.__evalCode[node_id] = code

    def get_eval_code(self, node_id: int) -> str:
        return self.__evalCode.get(node_id)

    def add_eval_pattern(self, node_id: int, pattern: int):
        if node_id not in self.__evalPatterns:
            self.__evalPatterns[node_id] = []
        if pattern not in self.__evalPatterns[node_id]:
            self.__evalPatterns[node_id].append(pattern)

    def get_eval_patterns(self, node_id: int) -> str:
        return self.__evalPatterns.get(node_id)

    def dfs(self, node: int) -> list:
        stack = [node]
        discovered = []
        while stack:
            v = stack.pop()
            if v in discovered:
                continue
            discovered.append(v)
            for c in self.get_any_children(v):
                stack.append(c)
            for p in self.get_any_parents(v):
                stack.append(p)
        return discovered

    def vectorize(self, node=None) -> np.ndarray:
        if node is None:
            nodes = self.get_node_ids()
        else:
            nodes = self.dfs(node)
        v = np.zeros(len(self.types))
        for node in nodes:
            if self.get_type(node) not in self.types:
                print(f"WARN: Type {self.get_type(node)} unknown. Skip node {node}..")
                continue
            v[self.types.index(self.get_type(node))] += 1
        return v

    # to add new edge types
    def to_dot(self):
        dot = "digraph ast {\n"
        dot += "node [shape=none];\n"

        for key in self.get_node_ids():
            if self.get_type(key) == "Dead" and len(self.get_parent(key)) == 0:
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
            table_style = "border='1' cellspacing='0' cellpadding='10' style='rounded'"
            if self.get_node_ast_ptr(key) is None:
                table_style += " color='#880000'"
            table = f"<TABLE {table_style}>"
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
                    dot += f"{key} -> {child} [weight=2];\n"
            if self.get_call_end(key) is not None:
                dot += f"{key} -> {self.get_call_end(key)} [weight=2;style=dotted];\n"
            if self.get_call_expr(key) is not None:
                dot += f"{key} -> {self.get_call_expr(key)} [constraint=false;color=purple];\n"
            if self.get_call_args(key) is not None:
                for arg_id in self.get_call_args(key):
                    dot += f"{key} -> {arg_id} [constraint=false;color=cyan];\n"
            if self.get_def_params(key) is not None:
                for arg_id in self.get_def_params(key):
                    dot += f"{key} -> {arg_id} [constraint=false;color=cyan];\n"
            if self.get_op_hands(key) is not None:
                dot += f"{key} -> {self.get_op_hands(key)[0]} [constraint=false;color=red];\n"
                dot += f"{key} -> {self.get_op_hands(key)[1]} [constraint=false;color=blue];\n"

        dot += "}\n"
        return dot
