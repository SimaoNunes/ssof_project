import sys
import json
import pprint
from nodes import *

VARIABLES = {}
SOURCES = []
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
        for target in node["targets"]:
            VARIABLES[target["id"]] = tainted
    # Flow information through a Call node
    elif node["ast_type"] == "Call":
        tainted = False
        for arg in node["args"]:
            if(propagate_flow(arg)):
                tainted = True
        if tainted:
            if('id' in node["func"].keys()):
                search_sanitizer_sink(node["func"]["id"])
            elif('attr' in node["func"].keys()):
                search_sanitizer_sink(node["func"]["attr"])
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
    # Flow information through a BinOp node
    elif node["ast_type"] == "BinOp":
        tainted = propagate_flow(node["left"]) or propagate_flow(node["right"])
        return tainted
    # Flwo information through a String node
    elif node["ast_type"] == "Str":
        return False

# Funtion that checks if a given function is a sanitizer or a sink
def search_sanitizer_sink(function_name):
    for vuln in PATTERNS:
        if function_name in vuln['sanitizers']:
            add_sanitizer_sink_('sanitizer', vuln['vulnerability'], function_name)
        elif function_name in vuln['sinks']:
            add_sanitizer_sink_('sink', vuln['vulnerability'], function_name)

# Function that adds a sanitizer or sink to a source
def add_sanitizer_sink_(element, vulnerability, function_name):
    for source in SOURCES:
        if source['vulnerability'] == vulnerability:
            if element == 'sanitizer':
                source['sanitizer'] = function_name
            else:
                source['sink'] = function_name
            
# Function that adds uninstatied variables to SOURCE list with all the vulnerbailities in patterns
def create_source_vulnerability(variable):
    for vuln in PATTERNS:
        dic = {}
        dic['vulnerability'] = vuln['vulnerability']
        dic['source'] = variable
        dic['sink'] = ""
        dic['sanitizer'] = ""
        SOURCES.append(dic)

# Prints the expected output. Only sources with sinks have a vulnerability
def printJSONOutput():
    for source in SOURCES:
        if source['sink'] != '':
            print(source)


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

    printJSONOutput()

    #print(VARIABLES)
    #print(SOURCES)

if __name__== "__main__":
	main()
