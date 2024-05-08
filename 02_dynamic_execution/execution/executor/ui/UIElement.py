class UIElement():

    resourceIdNumber = None
    resourceId = None
    automatorElement = None

    def __init__(self, resourceIdNumber=None, resourceId=None, automatorElement=None):
        self.resourceIdNumber = resourceIdNumber
        self.resourceId = resourceId
        self.automatorElement = automatorElement
