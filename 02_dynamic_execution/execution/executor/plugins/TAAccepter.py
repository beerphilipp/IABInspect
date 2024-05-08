import xml.etree.ElementTree as ET

from executor.output import Logger

class TAAcepter:

    triggerWords = ["Privacy Policy", "Terms of Service"]

    def __init__(self):
        pass


    def canHandle(self, screen) -> bool:
        xml = screen.uiXml
        # TODO: actual implementation
        return False
    
    def handle(self):
        Logger.info("TAAcepter handling the screen")
        pass
