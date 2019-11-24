import sys
import json
import pprint
from nodes import *

NODES = []
STORED_VARIABLES = []
PATTERNS = []

def main():
	# read json object of an AST of python code
	data = read_program(sys.argv[1])

	patterns = read_program(sys.argv[2])
	# visits all AST nodes
	visit_nodes(data)
	process_patterns(patterns)
	process_child_nodes(NODES)
	# identify and analyse if tainted variables are compromising slice of code
	#identify_tainted_variables()
	# print AST
	for node in NODES:
		node.print_info()
	#print(PATTERNS)


def update_patterns_vuln(vulnerability, i):
	patterns_types = ['sources', 'sanitizers', 'sinks']
	for pattern_type in patterns_types:
		for element in vulnerability[pattern_type]:
			if element not in PATTERNS[i][pattern_type]:
				PATTERNS[i][pattern_type].append(element)


def process_patterns(patterns):
	for vulnerability in patterns:
		present_vuln = ""
		index = 0
		for i, vuln in enumerate(PATTERNS):
			if vulnerability['vulnerability'] in vuln['vulnerability']:
				present_vuln = vulnerability['vulnerability']
				index = i
				break
		if present_vuln == "":
			PATTERNS.append(vulnerability)
		else:
			update_patterns_vuln(vulnerability, i)

	
def process_child_nodes(nodes):
	for node in nodes:
		if node.parent != None:
			node.parent.child.append(node)


def read_program(program_name):
	with open(program_name, 'rb') as data_file:
		return json.loads(data_file.read())


def visit_nodes(data, parent=None):

	data_type = data["ast_type"]

	##### module_node ####
	if data_type == "Module":
		node = module_node(None)
		NODES.append(node)
		for obj in data["body"]:
			visit_nodes(obj, node)

	##### Literals ####
	elif data_type == "Num":
		node = num_node(parent)
		NODES.append(node)

	elif data_type == "Str":
		node = str_node(parent)
		NODES.append(node)

	#### Variables ####
	elif data_type == "Name":
		node = name_node(data["id"], data["ctx"]["ast_type"], parent)
		if node.ctx == "Load" and node.id not in STORED_VARIABLES:
			node.tainted = True
		elif node.ctx == "Store" and node.id not in STORED_VARIABLES:
			STORED_VARIABLES.append(node.id)
		NODES.append(node)

	#### Expressions ####
	elif data_type == "Expr":
		node = expr_node(parent)
		NODES.append(node)
		visit_nodes(data["value"], node)

	elif data_type == "Call":
		if 'id' in data["func"].keys():
			node = call_node(data["func"]["id"], parent)	#WARNING there can be 2 funcs with same name but one is obj.attr and the other is not
		else:
			node = call_node(data["func"]["attr"], parent)
			objNode = name_node(data["func"]["value"]["id"], data["func"]["value"]["ctx"]["ast_type"], parent)
			NODES.append(objNode)
		
		possible_source_sink(node) #Check if name of the function is a source or sink in patterns

		NODES.append(node)
		for obj in data["args"]:
			visit_nodes(obj, node)

	elif data_type == "BinOp":
		node = binop_node(data["op"]["ast_type"], parent)
		NODES.append(node)
		visit_nodes(data["left"], node)
		visit_nodes(data["right"], node)

	#### Statements ####
	elif data_type == "Assign":
		node = assign_node(parent)
		NODES.append(node)
		for obj in data["targets"]:
			visit_nodes(obj, node)
		visit_nodes(data["value"], node)

	#### Control Flow ####

def possible_source_sink(node):
	function_name = node.name
	for vuln in PATTERNS:
		if function_name in vuln['sources']:
			node.tainted = true

'''
def identify_tainted_variables():
	tainted_variables = []
	for i, node in enumerate(NODES):
		if node.type == "Variable":
			var_name = node.id
			if node.ctx == "Load":
				tainted = True
				tainted_variables.append(node)
				if i > 0:
					for j in range(i-1):
						if NODES[j].type == "Variable" and NODES[j].id == var_name and NODES[j].ctx == "Store":
							tainted = False
							tainted_variables.pop()
							break
				node.set_tainted(tainted)

	tainted_nodes = tainted_variables.copy()
	for node in tainted_variables:
		while node.parent != None:
			if node.type == "Assign":
				taint_assign_target(node, tainted_nodes)
			node.parent.tainted = True
			tainted_nodes.append(node.parent)
			node = node.parent

	taint_equal_variables(tainted_nodes)

def taint_assign_target(assign_node, tainted_nodes):
	for node in NODES:
		if node.parent == assign_node:
			node.set_tainted(True)
			tainted_nodes.append(node)

def taint_equal_variables(tainted_nodes):
	for node in tainted_nodes:
		for node2 in NODES:
			if node2.type == "Variable" and node.type == "Variable" and node2.id == node.id:
				node2.set_tainted(True)
'''

if __name__== "__main__":
	main()
