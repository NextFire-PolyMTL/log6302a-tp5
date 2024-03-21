""" Read a .ast.json file and load id to a AST object """

import json
import sys
import gzip
from code_analysis import AST
from code_analysis.GraphException import ASTException


class ASTReader:

    def __init__(self):
        self.ast = None

    def read_ast(self, filename: str) -> AST:
        self.ast = AST()
        if filename.endswith(".gz"):
            with gzip.open(filename, 'rt', encoding='UTF-8') as file:
                self.__read_ast(file)
        else:
            with open(filename, 'r', encoding='UTF-8') as file:
                self.__read_ast(file)
        return self.ast

    def __read_ast(self, file):
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
            elif array[0] == "ast_succ":
                self.__readline_ast_succ(array)
            elif array[0] in ["token", "image"]:
                self.__readline_image(array)
            elif array[0] in ["line_begin", "line_end", "column_begin", "column_end", "token_begin", "token_end"]:
                self.__readline_position(array)
            elif array[0] in ["parsetree_pt", "scope_id"]:
                pass
            else:
                print(f"Unknown line type {array[0]}", file=sys.stderr)
        return self.ast

    def __readline_node_root(self, array):
        if len(array) != 2:
            raise ASTException(f"'node_root' should have 1 parameters - {array}")
        if type(array[1]) is not int:
            raise ASTException(f"'node_root' have wrong arguments type - {array}")
        self.ast.set_root(array[1])

    def __readline_filename(self, array: list):
        if len(array) != 2:
            raise ASTException(f"'filename' should have 1 parameters - {array}")
        if type(array[1]) is not str:
            raise ASTException(f"'filename' have wrong arguments type - {array}")
        self.ast.set_filename(array[1])

    def __readline_type(self, array):
        if len(array) != 3:
            raise ASTException(f"'node_type' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not str:
            raise ASTException(f"'node_type' have wrong arguments type - {array}")
        self.ast.set_type(array[1], array[2])

    def __readline_image(self, array):
        if len(array) != 3:
            raise ASTException(f"'{array[0]}' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not str:
            raise ASTException(f"'{array[0]}' have wrong arguments type - {array}")
        self.ast.set_image(array[1], array[2])

    def __readline_var_id(self, array):
        if len(array) != 3:
            raise ASTException(f"'{array[0]}' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'{array[0]}' have wrong arguments type - {array}")
        self.ast.set_var_id(array[1], array[2])

    def __readline_var_scope(self, array):
        if len(array) != 3:
            raise ASTException(f"'{array[0]}' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'{array[0]}' have wrong arguments type - {array}")
        self.ast.set_var_scope(array[1], array[2])

    def __readline_ast_succ(self, array):
        if len(array) != 3:
            raise ASTException(f"'ast_succ' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'ast_succ' have wrong arguments type - {array}")
        self.ast.add_edge(array[1], array[2])

    def __readline_position(self, array):
        if len(array) != 3:
            raise ASTException(f"'{array[0]}' should have 2 parameters - {array}")
        if type(array[1]) is not int or type(array[2]) is not int:
            raise ASTException(f"'{array[0]}' have wrong arguments type - {array}")

        pos = [None, None, None, None, None, None]
        if self.ast.get_position(array[1]) is not None:
            pos = self.ast.get_position(array[1])
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
        self.ast.set_position(array[1], pos)
