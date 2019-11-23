#########################################
####        General node class       ####
#########################################

class node:
    def __init__(self, parent, type):
        self.type          = type
        self.parent        = parent
        self.tainted       = False
        self.vulnerability = None
    def set_tainted(self, flag):
        self.tainted       = flag
    def set_vulnerability(self, name):
        self.vulnerability = name
    def print_info(self):
        print("################################")
        print("Type:", self.type, "\nParent:", self.parent,"\nTainted:", self.tainted, "\nVulnerability:", self.vulnerability)

#########################################
#### module_node (program root node) ####
#########################################

class module_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "module")
    def print_info(self):
        super().print_info()

#########################################
####             Literals            ####
#########################################

class str_node(node):
    def __init__(self, value, parent):
        node.__init__(self, parent, "str")
        self.value = value
    def print_info(self):
        super().print_info()
        print("str value:", self.value)

class num_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "num")
    def print_info(self):
        super().print_info()

#########################################
####            Variables            ####
#########################################

class var_node(node):
    def __init__(self, name, ctx, parent):
        node.__init__(self, parent, "variable")
        self.name = name
        self.ctx  = ctx
    def print_info(self):
        super().print_info()
        print("Name:", self.name, "\nCTX:", self.ctx)

#########################################
####           Expressions           ####
#########################################

class expr_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "expr")
    def print_info(self):
        super().print_info()

class call_node(node):
    def __init__(self, name, parent):
        node.__init__(self, parent, "call")
        self.name = name
    def print_info(self):
        super().print_info()
        print("Func name:", self.name)

class binop_node(node):
    def __init__(self, op, parent):
        node.__init__(self, parent, "binop")
        self.op = op
    def print_info(self):
        super().print_info()
        print("Op:", self.op)

#########################################
####            Statements           ####
#########################################

class assign_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "assign")
    def print_info(self):
        super().print_info()

#########################################
####           Control Flow          ####
#########################################

class if_node(node):
    pass

class while_node(node):
    pass
