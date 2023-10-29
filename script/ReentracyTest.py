import ast
import astor
import networkx as nx

# Define the Python code (replace this with your contract code)
contract_code = """
def main():
    if msg.sender == owner:
        contract_balance = call.value
    else:
        contract_balance = 0

def withdraw():
    if contract_balance > 0:
        selfdestruct(owner)
"""

# Parse the Python code to build the call graph
tree = ast.parse(contract_code)

# Create a directed graph to represent the call graph
call_graph = nx.DiGraph()


# Walk through the abstract syntax tree (AST) to build the call graph
def visit(node, parent_function=None):
    if isinstance(node, ast.FunctionDef):
        function_name = node.name
        if function_name not in call_graph:
            call_graph.add_node(function_name)
        if parent_function:
            call_graph.add_edge(parent_function, function_name)
        for child in ast.iter_child_nodes(node):
            visit(child, function_name)


visit(tree)

# Define the target call value
target_call_value = "call.value"

# Find the functions where target_call_value is used
target_functions = [node for node in call_graph.nodes() if target_call_value in astor.to_source(tree).split(node)]

# Assemble the functions found into a single smart contract
smart_contract = ""
for function_name in target_functions:
    function_code = astor.to_source(tree).split(function_name, 1)[1]
    smart_contract += function_code

print("----> ",smart_contract)