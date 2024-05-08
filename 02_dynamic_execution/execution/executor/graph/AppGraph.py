
from executor.graph.Screen import Screen

class AppGraph:
    """
        This class represents the graph of the application.
    """

    ENTRY_SCREEN = Screen(None, None, True, "ENTRY")
    CRASH_SCREEN = Screen(None, None, True, "CRASH")

    def __init__(self):
        self.entry = AppGraph.ENTRY_SCREEN
        self.screens = [AppGraph.ENTRY_SCREEN]
        self.transitions = []

    def maybeAddEdge(self, fromScreen, toScreen, transition):
        toScreen.setScreenContext(fromScreen)
        if (fromScreen.alike(toScreen)):
            # is there already a screen like this in the app graph?
            toScreen.release()
            return fromScreen
        

        # does the last screen look like this screen and there was no transaction? then we skip
        if (fromScreen.uiAlike(fromScreen.uiXml, toScreen.uiXml) and len(transition.transitions) == 0):
            toScreen.release()
            return fromScreen
        
        savedToScreen = self.getOrAddScreen(toScreen, fromScreen)
        transition.setFromScreen(fromScreen)
        transition.setToScreen(savedToScreen)
        self.transitions.append(transition)
        return savedToScreen

    def getOrAddScreen(self, screen, screenContext):
        screen.setScreenContext(screenContext)
        for s in self.screens:
            if s == screen:
                screen.release()
                return s
        
        # the screen is not yet part of the app graph, so we create it
        print("appending new screen")
        self.screens.append(screen)
        return screen
    
    def printAppGraph(self):
        print("--- Graph ---")
        for s in self.screens:
            print(str(s))
        for t in self.transitions:
            print(str(t))
        