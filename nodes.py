class node:
    def __init__(self):
        self.tainted       = False
        self.vulnerability = None
    def set_taited(self, flag):
        self.tainted       = flag
    def set_vulnerability(self, name):
        self.vulnerability = name
    def print_info(self):
        print("Tainted:",self.tainted,"Vulnerability:",self.vulnerability)

class module_node(node):
    def __init__(self):
        node.__init__(self)
        self.type     = "module"
    def print_info(self):
        print("###############")
        print("Type:",self.type)
        super().print_info()

class expr_node(node):
    def __init__(self, parent):
        node.__init__(self)
        self.type     = "expr"
        self.parent   = parent
    def print_info(self):
        print("###############")
        print("Type:",self.type,"Parent:",self.parent)
        super().print_info()

class call_node(node):
    def __init__(self, name, parent):
        node.__init__(self)
        self.type     = "call"
        self.parent   = parent
        self.name     = name
    def print_info(self):
        print("###############")
        print("Type",self.type,"Parent:",self.parent,"Func name:",self.name)
        super().print_info()

class binop_node(node):
    def __init__(self, op, parent):
        node.__init__(self)
        self.op       = op
        self.parent   = parent
    def print_info(self):
        print("###############")
        print("Op:",self.op,"Parent:",self.parent)
        super().print_info()

class srt_node(node):
    def __init__(self, value, parent):
        node.__init__(self)
        self.type     = "str"
        self.parent   = parent
        self.value    = value
    def print_info(self):
        print("###############")
        print("Type",self.type,"Parent:",self.parent,"str value:",self.value)
        super().print_info()

class assign_node(node):
    def __init__(self, parent):
        node.__init__(self)
        self.type     = "Assign"
        self.parent   = parent
    def print_info(self):
        print("###############")
        print("Type",self.type,"Parent:",self.parent)
        super().print_info()

class var_node(node):
    def __init__(self, name, ctx, parent):
        node.__init__(self)
        self.type     = "Variable"
        self.name     = name
        self.ctx      = ctx
        self.parent   = parent
    def print_info(self):
        print("###############")
        print("Type",self.type,"Parent:",self.parent,"Name:",self.name,"CTX:",self.ctx)
        super().print_info()
