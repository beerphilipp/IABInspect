import uiautomator2
import uuid
import os
from lxml import etree 

import executor.Context as Context
import executor.output.Logger as Logger
import executor.ADBUtils as ADBUtils

clickWhitelist = ["android.widget.Button"]

def get_clickable_elements_from_xml(xml):
    """
        Returns a list of clickable elements from the given XML.
    """
    doc = etree.XML(xml.encode())
    clickable_elements = doc.xpath("//node[@enabled='true' and @clickable='true' and not(ancestor::node[@class='android.webkit.WebView'])]")
    return clickable_elements

def get_clickable_elements_on_screen(serial):
    """
        Returns a list of all enabled and clickable elements on the screen.
        
        Even though uiautomator provides the device(clickable=True, enabled=True) method to only get clickable and enabled items,
        we cannot solely rely on this method, since we want to filter out clickable elements that are inside a WebView. Moreover,
        a UiSelector object does not have a method to get the parent of an element in order to check if it is inside a WebView.

        To solve this problem, we work on the XML of the screen. We first get the XML of the screen and query all clickable and enabled elements
        using an XPath expression. We then loop through the elements returned by uiautomator and use the instance of the element go get the corresponding XML node.
        We then check if the element is inside a WebView by checking if the element has a WebView as an ancestor. We only return the elements that are not 
        inside a WebView.
    """
    xml = get_xml_of_screen(serial)
    doc = etree.XML(xml.encode())
    clickable_enabled_xpath_expr = ".//node[@enabled='true' and @clickable='true']"
    not_parent_webview_xpath = "not(ancestor::node[@class='android.webkit.WebView'])"
    selected_nodes = doc.xpath(clickable_enabled_xpath_expr)

    device = uiautomator2.connect(serial)
    clickable_elements = device(clickable=True, enabled=True)
    
    result = []
    for clickable_element in clickable_elements:
        instance = clickable_element.selector['instance']
        xml_node = selected_nodes[instance]
        if (xml_node.xpath(not_parent_webview_xpath)):
            result.append(clickable_element)

    return result

def click(element):
    """
        Clicks on the given element. The element must be a UiObject.
    """
    element.click()

def click_by_id(serial, resourceId):
    """
        Clicks on the element with the given resource ID
    """
    device = uiautomator2.connect(serial)
    element = device(resourceIdMatches=resourceId)
    element.click()

def print_xml(serial):
    """
        Prints the XML of the current screen
    """
    device = uiautomator2.connect(serial)
    print(device.dump_hierarchy())


def take_screenshot(serial):
    """
        Takes a screenshot of the current screen
    """
    device = uiautomator2.connect(serial)
    screenshotName = os.path.join(Context.outputDir, str(uuid.uuid4()) + ".png")
    #device.screenshot(screenshotName)
    return screenshotName

def get_xml_of_screen(serial):
    """
        Returns the XML of the current screen
    """
    if (not ADBUtils.is_device_online(serial)):
        return None
    device = uiautomator2.connect(serial)
    return device.dump_hierarchy()