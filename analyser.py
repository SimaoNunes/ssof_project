import sys
import json
import pprint
from nodes import *

NODES = []

def main():

	data  = read_program(sys.argv[1])
	generate_nodes(data)
	
	for node in NODES:
		print("#-> node:")
		print(node.type)
		if node.parent != None:
			print(node.parent.type)
		print(node.tainted)


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
		node = call_node(data["func"]["id"],parent)
		NODES.append(node)
		for obj in data["args"]:
			generate_nodes(obj, node)
		
if __name__== "__main__":
	main()

