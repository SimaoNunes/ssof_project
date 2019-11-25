import sys
import json
import pprint
from nodes import *

VARIABLES = {}
VULNERABILITIES = []
PATTERNS = []

# reads json object from file
def read_program(program_name):
	with open(program_name, 'rb') as data_file:
		return json.loads(data_file.read())

# merge patterns with same vulnerability
def merge_patterns_vuln(vulnerability, i):
	patterns_types = ['sources', 'sanitizers', 'sinks']
	for pattern_type in patterns_types:
		for element in vulnerability[pattern_type]:
			if element not in PATTERNS[i][pattern_type]:
				PATTERNS[i][pattern_type].append(element)

# check if input patterns have duplicate vulnerabilities and merge them
def check_duplicate_vulnerabilities(patterns):
	for vulnerability in patterns:
		present_vuln = ""
		for i, vuln in enumerate(PATTERNS):
			if vulnerability['vulnerability'] in vuln['vulnerability']:
				present_vuln = vulnerability['vulnerability']
				break
		if present_vuln == "":
			PATTERNS.append(vulnerability)
		else:
			merge_patterns_vuln(vulnerability, i)

# return the name of a function node depending on its structure
def get_function_name(func_node):
    if('id' in func_node.keys()):
        return func_node["id"]
    elif('attr' in func_node.keys()):
        return func_node["attr"]

# verify if a function is a source
def verify_if_function_is_source(function_name):
    is_source = False
    for vuln in PATTERNS:
        if function_name in vuln['sources']:
            is_source = True
            dic = {}
            dic['vulnerability'] = vuln['vulnerability']
            dic['source'] = function_name
            dic['sink'] = ""
            dic['sanitizer'] = ""
            VULNERABILITIES.append(dic)
    return is_source

# check if a given function is a sanitizer or a sink
def search_sanitizer_sink(function_name):
    for vuln in PATTERNS:
        if function_name in vuln['sanitizers']:
            add_sanitizer_sink('sanitizer', vuln['vulnerability'], function_name)
        elif function_name in vuln['sinks']:
            add_sanitizer_sink('sink', vuln['vulnerability'], function_name)

# add a sanitizer or sink to a source
def add_sanitizer_sink(element, vulnerability, function_name):
    for source in VULNERABILITIES:
        if source['vulnerability'] == vulnerability:
            if element == 'sanitizer':
                source['sanitizer'] = function_name
            else:
                source['sink'] = function_name

# add uninstatied variables to source list with all the vulnerabilities in patterns
def create_source_vulnerability(variable):
    for vuln in PATTERNS:
        dic = {}
        dic['vulnerability'] = vuln['vulnerability']
        dic['source'] = variable
        dic['sink'] = ""
        dic['sanitizer'] = ""
        VULNERABILITIES.append(dic)

# print the expected output. Only sources with sinks have a vulnerability
def printJSONOutput():
    for vulnerability in VULNERABILITIES:
        if vulnerability['sink'] != '':
            print(vulnerability)

# propagates information on a given node of the ast
def propagate_flow(node):
    # Flow information through an Assign node
    if node["ast_type"] == "Assign":
        tainted = propagate_flow(node["value"])
        for target in node["targets"]:
            VARIABLES[target["id"]] = tainted
    # Flow information through a Call node
    elif node["ast_type"] == "Call":
        tainted = False
        func_name = get_function_name(node["func"])
        if verify_if_function_is_source(func_name):
            tainted = True
        for arg in node["args"]:
            if(propagate_flow(arg)):
                tainted = True
        if tainted:
            search_sanitizer_sink(func_name)
            print("ALERT THERE'S A VULNERABILITY")
        return tainted
    # Flow information through a Name node
    elif node["ast_type"] == "Name":
        if(node["id"] not in VARIABLES.keys() and node["ctx"]["ast_type"] == "Load"):
            VARIABLES[node["id"]] = True
            # Uninstantiazes variable - Create possible vulnerability for variable
            create_source_vulnerability(node["id"])
            return True
        else:
            return VARIABLES[node["id"]]
    # Flow information through a Binary Operation node
    elif node["ast_type"] == "BinOp":
        tainted = propagate_flow(node["left"]) or propagate_flow(node["right"])
        return tainted
    # Flow information through a String node
    elif node["ast_type"] == "Str":
        return False

# main function
def main():
	# read json object of an AST of python code
	ast = read_program(sys.argv[1])
	# read json object of patterns to identify vulnerabilities
	patterns = read_program(sys.argv[2])
	# check if in given pattern input there are 2 different patterns for the same vulnerability
	pprint.pprint(patterns)
	check_duplicate_vulnerabilities(patterns)
	pprint.pprint(PATTERNS)
    # check how information flows in code
	for obj in ast["body"]:
		propagate_flow(obj)
	# print output
	printJSONOutput()

    #print(VARIABLES)
    #print(VULNERABILITIES)


if __name__== "__main__":
	main()
