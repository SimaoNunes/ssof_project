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
        node.__init__(self, parent, "Module")
    def print_info(self):
        super().print_info()

#########################################
####             Literals            ####
#########################################

class num_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "Num")
    def print_info(self):
        super().print_info()

class str_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "Str")
    def print_info(self):
        super().print_info()

#########################################
####            Variables            ####
#########################################

class name_node(node):
    def __init__(self, id, ctx, parent):
        node.__init__(self, parent, "Variable")
        self.id = id
        self.ctx  = ctx
    def print_info(self):
        super().print_info()
        print("Id:", self.id, "\nCTX:", self.ctx)

#########################################
####           Expressions           ####
#########################################

class expr_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "Expr")
    def print_info(self):
        super().print_info()

class call_node(node):
    def __init__(self, name, parent):
        node.__init__(self, parent, "Call")
        self.name = name
    def print_info(self):
        super().print_info()
        print("Func name:", self.name)

class binop_node(node):
    def __init__(self, op, parent):
        node.__init__(self, parent, "Binop")
        self.op = op
    def print_info(self):
        super().print_info()
        print("Op:", self.op)

#########################################
####            Statements           ####
#########################################

class assign_node(node):
    def __init__(self, parent):
        node.__init__(self, parent, "Assign")
    def print_info(self):
        super().print_info()

#########################################
####           Control Flow          ####
#########################################

class if_node(node):
    pass

class while_node(node):
    pass
