""" Read a .cfg.json file and load id to a CFG object """

import json
import sys
import gzip
from code_analysis import CFG
from code_analysis.GraphException import ASTException


class CFGReader:

    def __init__(self):
        self.cfg = None

    def read_cfg(self, filename: str) -> CFG:
        self.cfg = CFG()
        if filename.endswith(".gz"):
            with gzip.open(filename, 'rt', encoding='UTF-8') as file:
                self.__read_cfg(file)
        else:
            with open(filename, 'r', encoding='UTF-8') as file:
                self.__read_cfg(file)
        return self.cfg

    def __read_cfg(self, file):
        while line := file.readline().rstrip():
            if line == "[" or line == "]":
                continue
            if line.endswith(","):
                line = line[:-1]
            array = json.loads(line)

            if array[0] == "node_root":
                self.__readline_node_root(array)
            elif array[0] == "filename":
                self.__readline_filename(array)
            elif array[0] == "type":
                self.__readline_type(array)
            elif array[0] == "var_id":
                self.__readline_var_id(array)
            elif array[0] == "var_scope":
                self.__readline_var_scope(array)
            elif array[0] == "cfg_succ":
                self.__readline_cfg_succ(array)
            elif array[0] in ["token", "image"]:
                self.__readline_image(array)
            elif array[0] in ["line_begin", "line_end", "column_begin", "column_end", "token_begin", "token_end"]:
                self.__readline_position(array)
            elif array[0] == "call_end":
                self.__readline_call_end(array)
            elif array[0] == "call_expr":
                self.__readline_call_expr(array)
            elif array[0] == "op_hands":
                self.__readline_op_hands(array)
            elif array[0] == "entry_func_name":
                self.__readline_entry_func_name(array)
            elif array[0] == "ast_pt":
                self.__readline_ast_pt(array)
            elif array[0] == "func_call_arg":
                self.__readline_func_call_arg(array)
            elif array[0] == "func_def_param":
                self.__readline_func_def_param(array)
            elif array[0] in ["scope_id"]:
                pass
            else:
                print(f"Unknown line type {array[0]}", file=sys.stderr)

    def __readline_node_root(self, array):
        if len(array) != 2:
            raise ASTException(f"'node_root' should have 1 parameters - {array}")
        if type(array[1]) is not int:
            raise ASTException(f"'node_root' have wrong arguments type - {array}")
        self.cfg.set_root(array[1])

    def __readline_filename(self, array: list):
        if len(array) != 2:
            raise ASTException(f"'filename' should have 1 parameters - {array}")
        if type(array[1]) is not str:
            raise ASTException(f"'filename' have wrong arguments type - {array}")
        self.cfg.set_filename(array[1])

    def __readline_type(self, array):
        if len(array) != 3:
            raise ASTException(f"'node_type' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not str:
            raise ASTException(f"'node_type' have wrong arguments type - {array}")
        self.cfg.set_type(array[1], array[2])

    def __readline_image(self, array):
        if len(array) != 3:
            raise ASTException(f"'{array[0]}' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not str:
            raise ASTException(f"'{array[0]}' have wrong arguments type - {array}")
        self.cfg.set_image(array[1], array[2])

    def __readline_var_id(self, array):
        if len(array) != 3:
            raise ASTException(f"'{array[0]}' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'{array[0]}' have wrong arguments type - {array}")
        self.cfg.set_var_id(array[1], array[2])

    def __readline_var_scope(self, array):
        if len(array) != 3:
            raise ASTException(f"'{array[0]}' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'{array[0]}' have wrong arguments type - {array}")
        self.cfg.set_var_scope(array[1], array[2])

    def __readline_cfg_succ(self, array):
        if len(array) != 3:
            raise ASTException(f"'cfg_succ' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'cfg_succ' have wrong arguments type - {array}")
        self.cfg.add_edge(array[1], array[2])

    def __readline_position(self, array):
        if len(array) != 3:
            raise ASTException(f"'{array[0]}' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'{array[0]}' have wrong arguments type - {array}")

        pos = [None, None, None, None, None, None]
        if self.cfg.get_position(array[1]) is not None:
            pos = self.cfg.get_position(array[1])
        if array[0] == "line_begin":
            pos[0] = array[2]
        elif array[0] == "line_end":
            pos[1] = array[2]
        elif array[0] == "column_begin":
            pos[2] = array[2]
        elif array[0] == "column_end":
            pos[3] = array[2]
        elif array[0] == "token_begin":
            pos[4] = array[2]
        elif array[0] == "token_end":
            pos[5] = array[2]
        else:
            raise ASTException(f"'{array[0]}' use unknown positional arguments key - {array}")
        self.cfg.set_position(array[1], pos)

    def __readline_ast_pt(self, array):
        if len(array) != 3:
            raise ASTException(f"'ast_pt' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'ast_pt' have wrong arguments type - {array}")
        self.cfg.set_node_ptr(array[2], array[1])

    def __readline_call_end(self, array):
        if len(array) != 3:
            raise ASTException(f"'call_end' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'call_end' have wrong arguments type - {array}")
        self.cfg.set_call(array[1], array[2])

    def __readline_call_expr(self, array):
        if len(array) != 3:
            raise ASTException(f"'call_expr' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'call_expr' have wrong arguments type - {array}")
        self.cfg.set_call_expr(array[1], array[2])

    def __readline_op_hands(self, array):
        if len(array) != 4:
            raise ASTException(f"'op_hands' should have 3 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int or (array[3] is not None and type(array[3]) is not int):
            raise ASTException(f"'op_hands' have wrong arguments type - {array}")
        self.cfg.set_op_hands(array[1], array[2], array[3])

    def __readline_entry_func_name(self, array):
        if len(array) != 3:
            raise ASTException(f"'entry_func_name' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not str:
            raise ASTException(f"'entry_func_name' have wrong arguments type - {array}")
        self.cfg.set_func_entry_node(array[1], array[2])

    def __readline_func_call_arg(self, array):
        if len(array) != 4:
            raise ASTException(f"'func_call_arg' should have 3 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int or type(array[3]) is not int:
            raise ASTException(f"'func_call_arg' have wrong arguments type - {array}")
        if len(self.cfg.get_call_args(array[1])) != array[2]:
            raise ASTException(f"'func_call_arg' wrong arguments index id - {array}")
        self.cfg.add_call_arg(array[1], array[3])

    def __readline_func_def_param(self, array):
        if len(array) != 4:
            raise ASTException(f"'func_def_param' should have 3 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int or type(array[3]) is not int:
            raise ASTException(f"'func_def_param' have wrong arguments type - {array}")
        if len(self.cfg.get_def_params(array[1])) != array[2]:
            raise ASTException(f"'func_def_param' wrong arguments index id - {array}")
        self.cfg.add_def_params(array[1], array[3])
