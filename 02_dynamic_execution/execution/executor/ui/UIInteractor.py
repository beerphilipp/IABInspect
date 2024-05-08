import time

import executor.ui.UIUtils as UIUtils
import executor.output.Logger as Logger
from executor.Awaitable import Awaitable
import executor.scripts.ScriptUtils as ScriptUtils
from executor.ui.UIElement import UIElement
import executor.ADBUtils as ADBUtils
from executor.actions.UIAction import UIAction
from executor.exceptions.NotInAppException import NotInAppException

# In case uiautomator2 does not work: https://github.com/openatx/uiautomator2/issues/906

class UIInteractor:
    """
    This class is responsible for interacting with the UI of the application under execution.
    """

    # We create a mapping of all onClick methods to their respective resource IDs
    clickMapping = None
    device = None
    ignore_buttons = []

    def __init__(self, package_name, fridaSession, device):
        self.package_name = package_name
        self.fridaSession = fridaSession
        self.device = device
        self.clickMapping = {}

    def simulateButtonClick(self, buttonClazz):

        if (not buttonClazz in self.clickMapping):
            self.updateClickMapping()

        if (not buttonClazz in self.clickMapping):
            Logger.error("Could not find any buttons of class " + buttonClazz)
            return
        
        buttonIds = self.clickMapping[buttonClazz]
        # TODO we simply take the first button. maybe make this more sophisticated later
        fullyQualifiedResourceId = buttonIds[0]["fullyQualifiedResourceId"]
        Logger.debug("Clicking on " + fullyQualifiedResourceId)
        UIUtils.click_by_id(self.device.device_name, fullyQualifiedResourceId)

    def get_possible_actions(self):
        time.sleep(3)
        top_package_name = ADBUtils.get_top_package_name(self.device.device_name)
        if (top_package_name != self.package_name):
            raise NotInAppException("Error while trying to get possible actions. The device is not in the app.", top_package_name)

        actions = []
        elements = self.get_possible_elements_and_on_click_listeners()
        for element in elements:
            uiElement = element[0]
            onClickMethod = element[1]
            uiAction = UIAction(uiElement, "click")
            uiAction.setReachableMethod(onClickMethod)
            actions.append(uiAction)
        return actions
    

    def get_possible_elements_and_on_click_listeners(self):    
        overwriteClickAwaiter, script = self.overwriteAllOnClick()
        allButtonsOverwritten = lambda message: message["event"] == "overwrite_finished"
        msg = overwriteClickAwaiter.waitUntil(allButtonsOverwritten, timeout=5) # we wait until all buttons are overwritten
        if (msg == None):
            raise Exception("Could not overwrite all buttons")
        clickableElements = UIUtils.get_clickable_elements_on_screen(self.device.device_name)
        clickableElements = [element for element in clickableElements if not element in UIInteractor.ignore_buttons]
        print(clickableElements)
        
        elements = []
        for clickableElement in clickableElements:
            isClickEvent = lambda message: message["event"] == "click"
            overwriteClickAwaiter.until(isClickEvent)
            UIUtils.click(clickableElement)
            top_package_name = ADBUtils.get_top_package_name(self.device.device_name)
            if (top_package_name != self.package_name):
                # due to this click we have left the app. we store this button to be ignored in the future
                UIInteractor.ignore_buttons.append(clickableElement)
                raise NotInAppException("Error while trying to get possible actions. The device is not in the app.", top_package_name)

            message = overwriteClickAwaiter.wait(0.5 * 1000)
            if message == None:
                onClickMethod = None
                resourceId = None
                resourceIdNumber = None
            else:
                Logger.debug(message)
                onClickMethod = message["method"]
                resourceId = message["resourceId"]
                resourceIdNumber = message["resourceIdNumber"]

            if (resourceIdNumber == -1):
                # The clickable element does not have a resource ID
                uiElement = UIElement(automatorElement=clickableElement)
            elif (onClickMethod == None):
                uiElement = UIElement(automatorElement=clickableElement)
            else:
                # TODO not super sure if this fully qualified resource id always holds true
                fullyQualifiedResourceId = clickableElement.info["packageName"] + ":id/" + resourceId
                uiElement = UIElement(resourceIdNumber=resourceIdNumber, resourceId=fullyQualifiedResourceId, automatorElement=clickableElement)

                elements.append((uiElement, onClickMethod))
        self.unhookAllOnClick(script)
        return elements





    def updateClickMapping(self):
        """
            We keep a mapping of onClickListeners to their respective resource IDs.
            This method updates the mapping by simulating a click on all clickable elements on the screen.
        """
        overwriteClickAwaiter, script = self.overwriteAllOnClick()
        allButtonsOverwritten = lambda message: message["event"] == "overwrite_finished"
        print("overwritten.")
        overwriteClickAwaiter.waitUntil(allButtonsOverwritten) # we wait until all buttons are overwritten
        
        clickable_elements = UIUtils.get_clickable_elements_on_screen(self.device.device_name)
        Logger.debug("Found " + str(len(clickable_elements)) + " clickable elements")
        
        for clickable_element in clickable_elements:
            isClickEvent = lambda message: message["event"] == "click"
            overwriteClickAwaiter.until(isClickEvent)
            UIUtils.click(clickable_element)
            message = overwriteClickAwaiter.wait()

            onClickMethod = message["method"]
            resourceId = message["resourceId"]
            resourceIdNumber = message["resourceIdNumber"]
            print(onClickMethod)

            if (resourceIdNumber == -1):
                # The clickable element does not have a resource ID
                text = clickable_element.get_text()
                className = clickable_element.info["className"]
                bounds = clickable_element.bounds()
                uiElement = UIElement(text=text, className=className, bounds=bounds)
            else:
                # TODO not super sure if this fully qualified resource id always holds true
                fullyQualifiedResourceId = clickable_element.info["packageName"] + ":id/" + resourceId
                uiElement = UIElement(resourceIdNumber=resourceIdNumber, resourceId=fullyQualifiedResourceId)

            if (not uiElement in self.clickMapping):
                self.clickMapping[uiElement] = []

            if (not onClickMethod in self.clickMapping[uiElement]):
                self.clickMapping[uiElement].append(onClickMethod)
        
        self.unhookAllOnClick(script)
        Logger.debug(self.clickMapping)

    def overwriteAllOnClick(self):
        Logger.debug("Overwriting all onClick methods")
        jscode = ScriptUtils.readScript("overwrite_ui_interactions.js", {})
        script = self.fridaSession.create_script(jscode)
        awaitable = Awaitable()
        script.on('message', awaitable.frida_add)
        script.load()
        return (awaitable, script)
    

    def overwriteAllOnTouch(self):
        Logger.debug("Overwriting all onTouch methods")
        jscode = ScriptUtils.readScript("overwrite_all_ontouch.js", {})
        script = self.fridaSession.create_script(jscode)
        awaitable = Awaitable()
        script.on('message', awaitable.frida_add)
        script.load()
        return (awaitable, script)
    

    def getClickMapping(self):
        return self.clickMapping
    
    def unhookAllOnClick(self, script):
        script.unload()

    