#########################################
####        General node class       ####
#########################################

class node:
    def __init__(self, parent, type):
        self.tainted       = False
        self.vulnerability = None
        self.parent        = parent
        self.type          = type
    def set_tainted(self, flag):
        self.tainted       = flag
    def set_vulnerability(self, name):
        self.vulnerability = name
    def print_info(self):
        print("Tainted:", self.tainted, "Vulnerability:", self.vulnerability)

#########################################
#### module_node (program root node) ####
#########################################

class module_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "module")
    def print_info(self):
        print("###############")
        print("Type:", self.type)
        super().print_info()

#########################################
####             Literals            ####
#########################################

class str_node(node):
    def __init__(self, value, parent):
        node.__init__(self, parent, "str")
        self.value = value
    def print_info(self):
        print("###############")
        print("Type", self.type, "Parent:", self.parent, "str value:", self.value)
        super().print_info()

#########################################
####            Variables            ####
#########################################

#########################################
####           Expressions           ####
#########################################

class expr_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "expr")
    def print_info(self):
        print("###############")
        print("Type:", self.type, "Parent:", self.parent)
        super().print_info()

#########################################
####            Statements           ####
#########################################

class assign_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "assign")
    def print_info(self):
        print("###############")
        print("Type", self.type, "Parent:", self.parent)
        super().print_info()

class call_node(node):
    def __init__(self, name, parent):
        node.__init__(self, parent, "call")
        self.name = name
    def print_info(self):
        print("###############")
        print("Type", self.type, "Parent:", self.parent, "Func name:", self.name)
        super().print_info()

class binop_node(node):
    def __init__(self, op, parent):
        node.__init__(self, parent, "binop")
        self.op = op
    def print_info(self):
        print("###############")
        print("Op:", self.op, "Parent:", self.parent)
        super().print_info()

class var_node(node):
    def __init__(self, name, ctx, parent):
        node.__init__(self, parent, "variable")
        self.name = name
        self.ctx  = ctx
    def print_info(self):
        print("###############")
        print("Type", self.type, "Parent:", self.parent, "Name:", self.name, "CTX:", self.ctx)
        super().print_info()

#########################################
####           Control Flow          ####
#########################################

class if_node(node):
    pass

class while_node(node):
    pass
