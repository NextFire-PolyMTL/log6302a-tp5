""" Define a CFG as a Graph with additional edge types and node information """

from code_analysis import Graph
from code_analysis.GraphException import CFGException
import json

class CFG(Graph):
    def __init__(self):
        super(CFG, self).__init__()
        self.__astPtr = {}
        self.__cfgPtr = {}
        self.__opHands = {}
        self.__funcEntryNode = {}
        self.__callExpr = {}
        self.__callBegins = {}
        self.__callEnds = {}
        self.__callArgs = {}
        self.__defParams = {}

    def delete_node(self, node_id: int):
        del self.__astPtr[node_id]
        del self.__cfgPtr[node_id]
        del self.__opHands[node_id]
        del self.__funcEntryNode[node_id]
        del self.__callExpr[node_id]
        del self.__callBegins[node_id]
        del self.__callEnds[node_id]
        del self.__callArgs[node_id]
        for key in self.__callArgs.keys():
            if node_id in self.__callArgs.get(key):
                self.__callArgs.get(key).remove(node_id)
        super(CFG, self).delete_node(node_id)

    def get_any_children(self, node_id: int) -> list:
        children = self.get_children(node_id).copy()
        if node_id in self.__callEnds:
            children.append(self.__callEnds.get(node_id))
        return children

    def get_any_parents(self, node_id: int) -> list:
        parents = self.get_parents(node_id).copy()
        if node_id in self.__callBegins:
            parents.append(self.__callBegins.get(node_id))
        return parents

    def get_call_args(self, node_id: int) -> list:
        if node_id in self.__callArgs:
            return self.__callArgs.get(node_id)
        return []

    def get_def_params(self, node_id: int) -> list:
        if node_id in self.__defParams:
            return self.__defParams.get(node_id)
        return []

    def get_node_ast_ptr(self, cfg_node: int) -> int:
        return self.__cfgPtr.get(cfg_node)

    def get_node_cfg_ptr(self, ast_node: int) -> int:
        return self.__astPtr.get(ast_node)

    def get_op_hands(self, node_id: int) -> list:
        return self.__opHands.get(node_id)

    def get_entry_func_name(self, node_id: int) -> str:
        return self.__funcEntryNode.get(node_id)

    def get_func_entry_nodes(self) -> list:
        return list(self.__funcEntryNode.keys())

    #def get_func_entry_node(self, func_name: str) -> int | None:
    def get_func_entry_node(self, func_name: str):
        for key in self.__funcEntryNode.keys():
            if self.__funcEntryNode.get(key) == func_name:
                return key
        return None

    def get_call_end(self, node_id: int) -> int:
        return self.__callEnds.get(node_id)

    def get_call_begin(self, node_id: int) -> int:
        return self.__callBegins.get(node_id)

    def get_call_expr(self, node_id: int) -> int:
        return self.__callExpr.get(node_id)

    def set_call(self, node_begin: int, node_end: int):
        self.__callBegins[node_end] = node_begin
        self.__callEnds[node_begin] = node_end

    def set_node_ptr(self, ast_node: int, cfg_node: int):
        self.__astPtr[ast_node] = cfg_node
        self.__cfgPtr[cfg_node] = ast_node

    def set_func_entry_node(self, node_id: int, func_name: str):
        self.__funcEntryNode[node_id] = func_name

    def set_op_hands(self, node_id: int, left: int, right: int):
        self.__opHands[node_id] = [left, right]

    def set_call_expr(self, node_begin: int, node_expr: int):
        self.__callExpr[node_begin] = node_expr

    def add_call_arg(self, id_call: int, id_arg: int):
        if id_call in self.__callArgs.keys():
            if id_arg in self.__callArgs[id_call]:
                raise CFGException(f"Duplicate func call argument ' : {id_call} - {id_arg}")
        else:
            self.__callArgs[id_call] = []
        self.__callArgs[id_call].append(id_arg)

    def add_def_params(self, id_def: int, id_param: int):
        if id_def in self.__defParams.keys():
            if id_param in self.__defParams[id_def]:
                raise CFGException(f"Duplicate def params argument ' : {id_def} - {id_param}")
        else:
            self.__defParams[id_def] = []
        self.__defParams[id_def].append(id_param)

    def to_json(self):
        out = "[\n"
        out += "  " + json.dumps(["node_root", self.get_root()]) + ",\n"
        if self.get_filename() is not None:
            out += "  " + json.dumps(["filename", self.get_filename()]) + ",\n"
        for key in self.get_node_ids():
            out += "  " + json.dumps(["type", key, self.get_type(key)]) + ",\n"
            if self.get_image(key) is not None:
                out += "  " + json.dumps(["image", key, self.get_image(key)]) + ",\n"
            if self.get_var_id(key) is not None:
                out += "  " + json.dumps(["var_id", key, self.get_var_id(key)]) + ",\n"
            if self.get_var_scope(key) is not None:
                out += "  " + json.dumps(["var_scope", key, self.get_var_scope(key)]) + ",\n"
            if self.get_call_end(key) is not None:
                out += "  " + json.dumps(["call_end", key, self.get_call_end(key)]) + ",\n"
            if self.get_call_expr(key) is not None:
                out += "  " + json.dumps(["call_expr", key, self.get_call_expr(key)]) + ",\n"
            if self.get_node_ast_ptr(key) is not None:
                out += "  " + json.dumps(["ast_pt", key, self.get_node_ast_ptr(key)]) + ",\n"
            if self.get_op_hands(key) is not None:
                out += "  " + json.dumps(
                    ["op_hands", key, self.get_op_hands(key)[0], self.get_op_hands(key)[1]]) + ",\n"
            if self.get_entry_func_name(key) is not None:
                out += "  " + json.dumps(["entry_func_name", key, self.get_entry_func_name(key)]) + ",\n"
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
                out += "  " + json.dumps(["cfg_succ", key, child]) + ",\n"
        out = out[:len(out) - 2]  # remove last comma
        out += "\n]"
        return out

    def to_dot(self):
        dot = "digraph ast {\n"
        dot += "node [shape=none];\n"

        for key in self.get_node_ids():
            if self.get_type(key) == "Dead" and len(self.get_parents(key)) == 0:
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
                    dot += f"{key} -> {child} [weight=10];\n"
            if self.get_call_end(key) is not None:
                dot += f"{key} -> {self.get_call_end(key)} [weight=10;style=dotted];\n"
            if self.get_call_expr(key) is not None:
                dot += f"{key} -> {self.get_call_expr(key)} [weight=1;color=purple];\n"
            if self.get_call_args(key) is not None:
                for arg_id in self.get_call_args(key):
                    dot += f"{key} -> {arg_id} [weight=1;color=cyan];\n"
            if self.get_def_params(key) is not None:
                for arg_id in self.get_def_params(key):
                    dot += f"{key} -> {arg_id} [weight=1;color=cyan];\n"
            if self.get_op_hands(key) is not None:
                dot += f"{key} -> {self.get_op_hands(key)[0]} [weight=1;color=red];\n"
                dot += f"{key} -> {self.get_op_hands(key)[1]} [weight=1;color=blue];\n"

        dot += "}\n"
        return dot
