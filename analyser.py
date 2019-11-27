import sys
import json

VARIABLES = {}
VULNERABILITIES = []
SOURCES = {}
SANITIZERS = {}
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
        function_name = func_node['attr']
        while True:
            if hasattr(func_node, 'value'):
                func_node = func_node['value']
            else:
                break
            function_name = func_node['attr'] + '.' + function_name
        return function_name

def check_if_sink(function_name, sources):
    for vuln in PATTERNS:
        if function_name in vuln['sinks']:
            create_vulnerability(vuln['vulnerability'], function_name, sources)

def check_if_sanitizer(function_name, sources):
    for vuln in PATTERNS:
        if function_name in vuln['sanitizers']:
            create_sanitizer(function_name, sources)

def create_sanitizer(function_name, sources):
    variable_name = sources[0][1]
    SANITIZERS[variable_name] = function_name

def unique(l):
    res = []
    for element in l:
        if element not in res:
            res.append(element)
    return res

# add a sanitizer or sink to a source
def create_vulnerability(vulnerability, function_name, sources):
    sources_list, sanitizers_list = get_source_from(function_name, sources)
    sanitizers_list = unique(sanitizers_list)
    for source in sources_list:
        dic = {}
        dic['vulnerability'] = vulnerability
        dic['source'] = source
        dic['sink'] = function_name
        dic['sanitizer'] = []
        for sanitizer in sanitizers_list:
            dic['sanitizer'].append(sanitizer)
        if len(dic['sanitizer']) == 0:
            dic['sanitizer'] = ''
        elif len(dic['sanitizer']) == 1:
            dic['sanitizer'] = dic['sanitizer'][0]
        VULNERABILITIES.append(dic)

# return name of tainted source
def get_source_from(sink, sources):
    print(sink, sources)
    sanitizers = []
    srcs = []
    for source in sources:
        type = source[0]
        name = source[1]
        if name in SANITIZERS.keys():
            sanitizers.insert(0, SANITIZERS[name])
        if type == 'var' and name == sink:
            srcs.append(name)
        elif type == 'func':
            srcs.append(name)
        else:
            t = get_source_from(name, VARIABLES[name][1])
            srcs += t[0]
            sanitizers += t[1]
    return srcs, sanitizers


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
    inputFile = sys.argv[1].split(".json")[0]
    outputFile = inputFile + '.output.json'
    f = open(outputFile, "w")
    for vulnerability in VULNERABILITIES:
        f.write(str(vulnerability))
        print(vulnerability)

# propagates information on a given node of the ast
def propagate_flow(node, implicit=''):
    # Flow information through an While node
    if node['ast_type'] == 'While':
        tainted_left = propagate_flow(node['test']['left'])
        for obj in node['test']['comparators']:
            tainted_comparator = propagate_flow(obj)
        if tainted_left[0]:
            implicit = tainted_left[1][0][1]
        elif tainted_comparator[0]:
            implicit = tainted_left[1][0][1]
        for obj in node['body']:
            propagate_flow(obj, implicit)
    # Flow information through an If node
    if node['ast_type'] == 'If':
        tainted = propagate_flow(node['test'])
        if tainted:
            implicit = node['test']['id']
        for obj in node['body']:
            propagate_flow(obj, implicit)
        for obj in node['orelse']:
            propagate_flow(obj, implicit)
    # Flow information through an Assign node
    if node['ast_type'] == 'Assign':
        tainted = propagate_flow(node['value'], implicit)
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
            check_if_sink(function_name, sources)
            check_if_sanitizer(function_name, sources)
        return tainted
    # Flow information through a Name node
    elif node['ast_type'] == 'Name':
        if node['id'] not in VARIABLES.keys() and node['ctx']['ast_type'] == 'Load':
            VARIABLES[node['id']] = (True, [('var', node['id'])])              # WARNING conflito de nomes de funcoes e variaveis iguais!!!!!!!!!
            # Uninstantiazed variable - Source for vulnerability
            add_to_sources(node['id'])
            return VARIABLES[node['id']]
        else:
            if VARIABLES[node['id']][0] or implicit:
                return (True, [('var', node['id'])])
            else:
                return VARIABLES[node['id']]
    # Flow information through a Binary Operation node
    elif node['ast_type'] == 'BinOp':
        list = []
        left = propagate_flow(node['left'], implicit)
        right = propagate_flow(node['right'], implicit)
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
        if implicit == '':
            return (False, [])
        else:
            return (True, [('var', implicit)])
    # Flow information through a Number node
    elif node['ast_type'] == 'Num':
        if implicit == '':
            return (False, [])
        else:
            return (True, [('var', implicit)])
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



if __name__== '__main__':
    main()
