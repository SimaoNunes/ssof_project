import sys
import json
import pprint
from nodes import *

NODES = []

def main():

	data  = read_program(sys.argv[1])
	generate_nodes(data)

	identify_tainted_variables()
	
	#for node in NODES:
	#	node.print_info()


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
		if 'id' in data["func"].keys():
			node = call_node(data["func"]["id"], parent)
		else:
			node = call_node(data["func"]["attr"], parent)
			node2 = var_node(data["func"]["value"]["id"], data["func"]["value"]["ctx"]["ast_type"], parent)
			NODES.append(node2)
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

	elif data_type == "Assign":
		node = assign_node(parent)
		NODES.append(node)
		for obj in data["targets"]:
			generate_nodes(obj, node)
		generate_nodes(data["value"], node)

	elif data_type == "Name":
		node = var_node(data["id"], data["ctx"]["ast_type"], parent)
		NODES.append(node)

def identify_tainted_variables():
	tainted_variables = []
	for i, node in enumerate(NODES):
		if node.type == "Variable":
			var_name = node.name
			if node.ctx == "Load":
				tainted = True
				tainted_variables.append(node)
				if i > 0:
					for j in range(i-1):
						if NODES[j].type == "Variable" and NODES[j].name == var_name and NODES[j].ctx == "Store":
							tainted = False
							tainted_variables.pop()
							break
				node.tainted = tainted

	tainted_nodes = tainted_variables.copy()
	for node in tainted_variables:
		while node.parent != None:
			if node.type == "Assign":
				taint_assign_target(node, tainted_nodes)
			node.parent.tainted = True
			tainted_nodes.append(node.parent)
			node = node.parent


	taint_equal_variables(tainted_nodes)

	for node in NODES:
		print(node.print_info())


def taint_assign_target(assign_node, tainted_nodes):
	for node in NODES:
		if node.parent == assign_node:
			node.set_taited(True)
			tainted_nodes.append(node)

def taint_equal_variables(tainted_nodes):
	for node in tainted_nodes:
		for node2 in NODES:
			if node2.type == "Variable" and node.type == "Variable" and node2.name == node.name:
				node2.set_taited(True)

if __name__== "__main__":
	main()

