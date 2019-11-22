import sys
import json
import pprint
from nodes import *

NODES = []

def main():

	data  = read_program(sys.argv[1])
	generate_nodes(data)
	
	for node in NODES:
		node.print_info()


def read_program(program_name):
	with open(program_name, 'rb') as data_file:
		return json.loads(data_file.read())


def generate_nodes(data, parent=None):
	
	data_type = data["ast_type"]

	if data_type == "Module":    
		node = module_node()
		NODES.append(node)
		for obj in data["body"]:
			generate_nodes(obj, node)
	
	elif data_type == "Expr":
		node = expr_node(parent)
		NODES.append(node)
		generate_nodes(data["value"], node)

	elif data_type == "Call":
		node = call_node(data["func"]["id"], parent)
		NODES.append(node)
		for obj in data["args"]:
			generate_nodes(obj, node)

	elif data_type == "BinOp":
		node = binop_node(data["op"]["ast_type"], parent)
		NODES.append(node)
		generate_nodes(data["left"], node)
		generate_nodes(data["right"], node)

	elif data_type == "Str":
		node = srt_node(data["s"], parent)
		NODES.append(node)
		
if __name__== "__main__":
	main()

