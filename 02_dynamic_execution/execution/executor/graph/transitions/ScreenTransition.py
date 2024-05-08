class ScreenTransition():
    """
        Represents a transition in the app graph.
    """

    def __init__(self):
        self.transitions = []
        self.fromScreen = None
        self.toScreen = None

    def setFromScreen(self, fromScreen):
        self.fromScreen = fromScreen

    def setToScreen(self, toScreen):
        self.toScreen = toScreen

    def addTransition(self, transition):
        self.transitions.append(transition)

    def __str__(self) -> str:
        string = "{Transition: from " + str(self.fromScreen) + " to " + str(self.toScreen)
        for t in self.transitions:
            string += "\n\t" + str(t)
        string += "}"
        return string 
    
    def __eq__(self, other):
        if not isinstance(other, ScreenTransition):
            return False
        
        if self.fromScreen != other.fromScreen:
            return False
        
        if self.toScreen != other.toScreen:
            return False

        if (self.transitions != other.transitions):
            return False
            
        return True