import os
from lxml import etree
import executor.ui.UIUtils as UIUtils
import executor.ADBUtils as ADBUtils

from executor.graph.DistinguishableScreenElement import DistinguishableScreenElement

class Screen:

    def capture_screen(device):
        activity = ADBUtils.get_top_activity(device.device_name)
        ui_xml = UIUtils.get_xml_of_screen(device.device_name)
        
        return Screen(activity, ui_xml, False)

    def __init__(self, activity, ui_xml, is_dummy = False, dummy_name = None):
        self.activity = activity
        self.ui_xml = ui_xml
        self.is_dummy = False

        if (is_dummy):
            self.is_dummy = True
            self.activity = dummy_name
            self.ui_xml = dummy_name
            self.distinguishable_elements = []
        else:
            self.distinguishable_elements = self._get_distinguishable_elements()

    def _get_distinguishable_elements(self):
        """
            Get the distinguishable elements of the screen.
        """
        distinguishable_elements = []
        if (self.ui_xml == None):
            return []
        
        elements =  UIUtils.get_clickable_elements_from_xml(self.ui_xml)
        for element in elements:
            screen_element = DistinguishableScreenElement(element.get("package"), element.get("class"), element.get("text"), element.get("content-desc"), element.get("resource-id"))
            distinguishable_elements.append(screen_element)
        return distinguishable_elements

    def __str__(self) -> str:
        string = f"Activity: {self.activity}, amount of distinguishable elements: {len(self.distinguishable_elements)}\n"
        return string
    
    def __eq__(self, other) -> bool:
        if (other == None):
            return False
        
        if (type(other) != Screen):
            return False
        
        if (self.is_dummy != other.is_dummy):
            return False
        
        if (self.activity != other.activity):
            return False
        
        if (not self.distinguishable_elements == other.distinguishable_elements):
            return False
        
        return True
    
    def uiAlike(self, thisUiXml, otherUiXml) -> bool:
        """
            Checks whether two UI XMLs are alike.
        """
        if (thisUiXml == None and otherUiXml == None):
            return True
        
        if (thisUiXml == None or otherUiXml == None):
            return False

        try:
            docThis = etree.XML(thisUiXml.encode())
            docOther = etree.XML(otherUiXml.encode())
        except Exception as e:
            raise e
        numElementThis = sum(1 for _ in docThis.iter("*"))
        numElementOther = sum(1 for _ in docOther.iter("*"))
        return numElementOther == numElementThis

    def toDict(self):
        return {
            "activity": self.activity,
            "distinguishable_elements": [element.to_dict() for element in self.distinguishable_elements]
        }