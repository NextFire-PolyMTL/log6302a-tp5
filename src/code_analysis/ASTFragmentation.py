from code_analysis import AST

fragmentTypes = [
    "FunctionStatement",
    "MethodStatement",
    "PublicMethodStatement",
    "PrivateMethodStatement",
    "ProtectedMethodStatement",
    "AbstractMethodStatement",
    "AbstractPublicMethodStatement",
    "AbstractProtectedMethodStatement",
    "AbstractPrivateMethodStatement",
    "LambdaFunctionStatement"
]


def AST_fragmentation(ast: AST) -> list:
    fragments = []
    for node in ast.get_node_ids():
        if ast.get_type(node) in fragmentTypes:  # New fragment found: add to the list and remove edge with parent
            fragments.append(node)
            parents = ast.get_parents(node).copy()
            for p in parents:
                ast.get_children(p).remove(node)
            ast.get_parents(node).clear()
    return fragments

