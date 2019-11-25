import sys
import json
import pprint
from nodes import *

VARIABLES = {}
VULNERABILITIES = []
SOURCES = {}
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

# get input patterns while checking if they have duplicate vulnerabilities and merge them
def process_patterns(patterns):
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
    for vulnerability in PATTERNS:
        SOURCES[vulnerability["vulnerability"]] = []

# return the name of a function node depending on its structure
def get_function_name(func_node):
    if('id' in func_node.keys()):
        return func_node["id"]
    elif('attr' in func_node.keys()):
        return func_node["attr"]

# check if a given function is a sanitizer or a sink
def check_if_sanitizer_or_sink(function_name):
    for vuln in PATTERNS:
        if function_name in vuln['sanitizers']:
            add_sanitizer_or_sink('sanitizer', vuln['vulnerability'], function_name)
        elif function_name in vuln['sinks']:
            add_sanitizer_or_sink('sink', vuln['vulnerability'], function_name)

# add a sanitizer or sink to a source
def add_sanitizer_or_sink(element, vulnerability, function_name):
        dic = {}
        dic['vulnerability'] = vulnerability
        dic['source'] = SOURCES[vulnerability][0] #FIXME THIS IS PUTTING ALL SOURCES TO VULN! WE MUST FOLLOW THE FLOW FROM A GIVEN SOURCE
        if element == 'sanitizer':
            dic['sanitizer'] = function_name
            dic['sink'] = ""
        else:
            dic['sanitizer'] = ""
            dic['sink'] = function_name
        VULNERABILITIES.append(dic)

# add uninstatiated variables to all sources list
def add_to_sources(variable):
    for vuln in PATTERNS:
        SOURCES[vuln["vulnerability"]].append(variable)         #WARNING! IF VARIABLE HAS FUNCTION NAME THERE'S A BUGGGGG

# verify if a function is a source
def is_function_source(function_name):
    is_source = False
    for vuln in PATTERNS:
        if function_name in vuln['sources']:
            is_source = True
            SOURCES[vuln["vulnerability"]].append(function_name)        #WARNING! IF VARIABLE HAS FUNCTION NAME THERE'S A BUGGGGG
    return is_source

# print the expected output. Only sources with sinks have a vulnerability
def printVulnerabilities():
    for vulnerability in VULNERABILITIES:
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
        func_name = get_function_name(node["func"])		#WARNING what about 2 functions with same name? One is function the other is attribute
        if is_function_source(func_name):				#FIXME If function is source there's no need to propagate flow on args, problably ??
            tainted = True
        for arg in node["args"]:
            if propagate_flow(arg):
                tainted = True
        if tainted:
            check_if_sanitizer_or_sink(func_name)
        return tainted
    # Flow information through a Name node
    elif node["ast_type"] == "Name":
        if node["id"] not in VARIABLES.keys() and node["ctx"]["ast_type"] == "Load":
            VARIABLES[node["id"]] = True
            # Uninstantiazed variable - Source for vulnerability
            add_to_sources(node["id"])
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
    # Flow information through a Number node
    elif node["ast_type"] == "Num":
        return False
    # Flow information through a Number node
    elif node["ast_type"] == "Expr":
        return propagate_flow(node["value"])


# main function
def main():
    # read json object of an AST of python code
    ast = read_program(sys.argv[1])
    # read json object of patterns to identify vulnerabilities
    patterns = read_program(sys.argv[2])
    # instantiates PATTERNS and SOURCES
    process_patterns(patterns)
    # check how information flows in code
    for obj in ast["body"]:
        propagate_flow(obj)
    # print output
    printVulnerabilities()

    #print(VARIABLES)
    #print(VULNERABILITIES)


if __name__== "__main__":
    main()
