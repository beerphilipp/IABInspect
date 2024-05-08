import json

from executor.graph.transitions.ScreenTransition import ScreenTransition

def isArtificialClass(cls):
    return cls == "dummyMainClass" or cls == "entryClass"


def copyTransitionPath(transitionPath):
    path = []
    for transition in transitionPath:
        t = ScreenTransition()
        t.fromScreen = transition.fromScreen
        t.toScreen = transition.toScreen
        for action in transition.transitions:
            t.addTransition(action)
        path.append(t)
    return path