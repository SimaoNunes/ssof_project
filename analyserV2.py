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
        present_vuln = ''
        for i, vuln in enumerate(PATTERNS):
            if vulnerability['vulnerability'] in vuln['vulnerability']:
                present_vuln = vulnerability['vulnerability']
                break
        if present_vuln == '':
            PATTERNS.append(vulnerability)
        else:
            merge_patterns_vuln(vulnerability, i)
    for vulnerability in PATTERNS:
        SOURCES[vulnerability['vulnerability']] = []

# return the name of a function node depending on its structure
def get_function_name(func_node):
    if 'id' in func_node.keys():
        return func_node['id']
    elif 'attr' in func_node.keys():
        return func_node['attr']


# check if a given function is a sanitizer or a sink
def check_if_sanitizer_or_sink(function_name, sources):
    for vuln in PATTERNS:
        if function_name in vuln['sanitizers']:
            add_sanitizer_or_sink('sanitizer', vuln['vulnerability'], function_name, sources)
        elif function_name in vuln['sinks']:
            add_sanitizer_or_sink('sink', vuln['vulnerability'], function_name, sources)

# add a sanitizer or sink to a source
def add_sanitizer_or_sink(element, vulnerability, function_name, sources):
    for source in sources:
        dic = {}
        dic['vulnerability'] = vulnerability
        dic['source'] = get_source_from(function_name, source)
        dic['sink'] = function_name
        dic['sanitizer'] = ''
    VULNERABILITIES.append(dic)

# return name of tainted source
def get_source_from(sink, source):
    name = source[1]
    if source[0] == 'var' and name == sink:
        return name
    elif source[0] == 'func':
        return name
    else:
        for src in VARIABLES[name][1]:
            return get_source_from(name, src)


# add uninstatiated variables to all sources list
def add_to_sources(variable):
    for vuln in PATTERNS:
        SOURCES[vuln['vulnerability']].append(variable)         # WARNING! IF VARIABLE HAS FUNCTION NAME THERE'S A BUGGGGG

# verify if a function is a source
def is_function_source(function_name):
    is_source = False
    for vuln in PATTERNS:
        if function_name in vuln['sources']:
            is_source = True
            SOURCES[vuln['vulnerability']].append(function_name)        # WARNING! IF VARIABLE HAS FUNCTION NAME THERE'S A BUGGGGG
    return is_source

# print the expected output. Only sources with sinks have a vulnerability
def printVulnerabilities():
    for vulnerability in VULNERABILITIES:
        print(vulnerability)

# propagates information on a given node of the ast
def propagate_flow(node):
    # Flow information through an Assign node
    if node['ast_type'] == 'Assign':
        tainted = propagate_flow(node['value'])
        for target in node['targets']:
            VARIABLES[target['id']] = tainted
    # Flow information through a Call node
    elif node['ast_type'] == 'Call':
        tainted = (False, [])
        sources = []
        function_name = get_function_name(node['func'])		# WARNING what about 2 functions with same name? One is function the other is attribute
        if is_function_source(function_name):
            sources.append(('func', function_name))
            tainted = (True, sources)
        for arg in node['args']:
            flow = propagate_flow(arg)
            if flow[0]:
                for src in flow[1]:
                    sources.append(src)
                tainted = (True, sources)
        if tainted[0]:
            check_if_sanitizer_or_sink(function_name, sources)
        return tainted
    # Flow information through a Name node
    elif node['ast_type'] == 'Name':
        if node['id'] not in VARIABLES.keys() and node['ctx']['ast_type'] == 'Load':
            VARIABLES[node['id']] = (True, [('var', node['id'])])              # WARNING conflito de nomes de funcoes e variaveis iguais!!!!!!!!!
            # Uninstantiazed variable - Source for vulnerability
            add_to_sources(node['id'])
            return VARIABLES[node['id']]
        else:
            if VARIABLES[node['id']][0]:
                return (True, [('var', node['id'])])
            else:
                return VARIABLES[node['id']]
    # Flow information through a Binary Operation node
    elif node['ast_type'] == 'BinOp':
        list = []
        left = propagate_flow(node['left'])
        right = propagate_flow(node['right'])
        tainted = left[0] or right[0]
        if left[0]:
            for source in left[1]:
                list.append(source)
        if right[0]:
            for source in right[1]:
                list.append(source)
        return (tainted, list)
    # Flow information through a String node
    elif node['ast_type'] == 'Str':
        return (False, [])
    # Flow information through a Number node
    elif node['ast_type'] == 'Num':
        return (False, [])
    # Flow information through a Number node
    elif node['ast_type'] == 'Expr':
        return propagate_flow(node['value'])


# main function
def main():
    # read json object of an AST of python code
    ast = read_program(sys.argv[1])
    # read json object of patterns to identify vulnerabilities
    patterns = read_program(sys.argv[2])
    # instantiates PATTERNS and SOURCES
    process_patterns(patterns)
    # check how information flows in code
    for obj in ast['body']:
        propagate_flow(obj)
    # print output
    printVulnerabilities()

    #print(VARIABLES)
    #print(VULNERABILITIES)


if __name__== '__main__':
    main()
