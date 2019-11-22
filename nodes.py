class node:
    def __init__(self):
        self.tainted  = False
        self.vulnerability = None
    def set_taited(self, flag):
        self.tainted  = flag
    def set_vulnerability(self, name):
        self.vulnerability = name

class module_node(node):
    def __init__(self):
        node.__init__(self)
        self.type     = "module"
        self.parent   = None

class expr_node(node):
    def __init__(self, parent):
        node.__init__(self)
        self.type     = "expr"
        self.parent   = parent

class call_node(node):
    def __init__(self, name, parent):
        node.__init__(self)
        self.type     = "call"
        self.parent   = parent
        self.name     = name