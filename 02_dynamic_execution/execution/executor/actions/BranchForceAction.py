class BranchForceAction:

    forcer = None
    clazz = None
    name = None
    forceTo = None

    def __init__(self, forcer, clazz, name, forceTo):
        self.forcer = forcer
        self.clazz = clazz
        self.name = name
        self.forceTo = forceTo

    def perform(self):
        self.forcer.forceBranchCondition(self.clazz, self.name, self.forceTo)
        pass