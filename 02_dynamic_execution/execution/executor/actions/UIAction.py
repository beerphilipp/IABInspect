class UIAction:

    source = None
    uiElement = None
    action = None
    reachableMethod = None
    destination = None

    def __init__(self, uiElement, action):
        self.uiElement = uiElement
        self.action = action # for now every action is a click

    def setReachableMethod(self, reachableMethod):
        self.reachableMethod = reachableMethod
    
    def perform(self):
        if (self.action == "click"):
            self.uiElement.automatorElement.click()
        else:
            print("WE DO NOT SUPPORT ANY OTHER ACTIONS THAN CLICKS YET")
    
    def revert(self):
        print("WE DO NOT SUPPORT REVERTING ACTIONS YET")

    def toDict(self):
        dict = {}
        dict["uiElement"] = str(self.uiElement)
        dict["action"] = self.action
        dict["subType"] = self.action
        return dict

    def __str__(self) -> str:
        return f"UIAction: {self.uiElement} - {self.action}"

    def __eq__(self, other) -> bool:
        """
            Overwrites the default equals method.
            Two UIActions are equal if their uiElement and action are equal.
        """
        if not isinstance(other, UIAction):
            return False
        
        if not self.uiElement == other.uiElement:
            return False
        
        if not self.action == other.action:
            return False
        
        return True