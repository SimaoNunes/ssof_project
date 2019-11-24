import sys
import json
import pprint
from nodes import *

VARIABLES = {}
PATTERNS = []

def read_program(program_name):
	with open(program_name, 'rb') as data_file:
		return json.loads(data_file.read())

def update_patterns_vuln(vulnerability, i):
	patterns_types = ['sources', 'sanitizers', 'sinks']
	for pattern_type in patterns_types:
		for element in vulnerability[pattern_type]:
			if element not in PATTERNS[i][pattern_type]:
				PATTERNS[i][pattern_type].append(element)


def check_duplicate_vulnerabilities(patterns):
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

def propagate_flow(node):
    # Flow information through an Assign node
    if node["ast_type"] == "Assign":
        tainted = propagate_flow(node["value"])
        for target in node["target"]:
            VARIABLES[target["id"]] = tainted
    # Flow information through a Call node
    elif node["ast_type"] == "Call":
        tainted = False
        for arg in node["args"]:
            if(propagate_flow(arg)):
                tainted = True
        if(tainted and node["func"]["attr"] == "execute")
            print("ALERT THERE'S A VULNERABILITY")
        return tainted
    # Flow information through a Name node
    elif node["ast_type"] == "Name":
        if(node["id"] not in VARIABLES.keys() and node["ctx"]["ast_type"] == "Load"):
            VARIABLES[node["id"]] = True
            return True
        else:
            return VARIABLES[node["id"]]
    # Flow information through a BinOp node
    elif node["ast_type"] == "BinOp":
        tainted = propagate_flow(node["left"]) || propagate_flow(node["right"])
        return tainted
    # Flwo information through a String node
    elif node["ast_type"] == "Str":
        return False




def main():
    # read json object of an AST of python code
    ast = read_program(sys.argv[1])
    # read json object of patterns to identify vulnerabilities
    patterns = read_program(sys.argv[2])
    # check if in given pattern input there are 2 different patterns for the same vulnerability
    check_duplicate_vulnerabilities(patterns)
    # check how information flows in code
    for obj in ast["body"]:
        propagate_flow(obj)

if __name__== "__main__":
	main()
