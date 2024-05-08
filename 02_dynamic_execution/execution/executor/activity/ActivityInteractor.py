import time
import itertools

import executor.output.Logger as Logger
import executor.ADBUtils as ADBUtils
import executor.scripts.ScriptUtils as ScriptUtils

from executor.Awaitable import Awaitable
from executor.actions.SysAction import SysAction
from executor.exceptions.FridaException import FridaException
from executor.exceptions.CrashException import CrashException

ACTIVITY_LAUNCH_WAIT_TIMEOUT = 2

INTENT_SPACE = {
    "String": ["https://www.33website44.com", "33String44"],
    "boolean": [True, False],
    "int": [0, 1], 
    "float": [1.0],
    "long": [1],
    "short": [1],
    "char": ["a"],
    "byte": [1]
}
# TODO: Add parcellable + bundle

class ActivityInteractor:
    """
        This class is responsible for interacting with the activities of an application.
    """
    
    device = None
    
    def __init__(self, executor, device):
        self.executor = executor
        self.device = device

    def get_possible_sys_actions(self, activity_name: str, data: str, extras: dict[str, str]) -> list[SysAction]:
        """
            Returns a list of possible sys actions that can be performed on the given activity.

            :param activity_name: The name of the activity
            :param data: The data that can be used in the sys action
            :param extras: The extras that can be used in the sys action
            :return: A list of possible sys actions
        """
            # TODO: handle data. there may be others (except notEmpty). We need to check those.
        data = [None]
        #if data == None:
        #    data = [None]
        #if data == "notEmpty":
        #    data = ["https://www.google.at"]

        # We check if there are types used in the extras that are not in the INTENT_SPACE.
        # If this is the case, we raise an exception, because that means that we have to extend the INTENT_SPACE.
        unknown_types = set(extras.values()) - set(INTENT_SPACE.keys())
        if unknown_types:
            raise Exception("Unknown types in extras: " + str(unknown_types))
        
        extras_combinations = []
        for var_name, var_type in extras.items():
            var_space = INTENT_SPACE[var_type]
            extras_combinations.append([(var_name, value) for value in var_space])
        all_extras_combinations = list(itertools.product(*extras_combinations))
        
        for i in range(len(all_extras_combinations)):
            combinations = {}
            for extra in all_extras_combinations[i]:
                combinations[extra[0]] = extra[1]
            all_extras_combinations[i] = combinations

        sys_actions = []
        for extras_combination in all_extras_combinations:
            for d in data:
                sys_action = SysAction(self.executor, activity_name, extras_combination, d)
                sys_actions.append(sys_action)
        
        return sys_actions

    
    def open_activity(self, target_activity_name, extras=None, data=None):
        """
            Opens the activity with the given name
        """
        current_activity = ADBUtils.get_top_activity(self.device.device_name)

        # we do this to support the case where we used an old version of the static analyzer
        all_activities = self.executor.activities
        for activity in all_activities:
            if (activity["name"] == current_activity):
                if activity['aliasFor'] != None:
                    current_activity = activity['aliasFor']
                break
        
        app_crashed = ADBUtils.check_app_crash(self.device.device_name, self.device.package_name)
        
        if (app_crashed):
            raise CrashException("App crashed before opening activity")
        
        try:
            Logger.debug(f"Opening activity {target_activity_name} from {current_activity} with extras {extras} and data {data}")
            jscode = ScriptUtils.readScript("open_activity.js", {"currentActivityName": current_activity, "targetActivityName": target_activity_name, "extras": extras, "data": data})
            script = self.device.frida_session.create_script(jscode)
            
            awaitable = Awaitable()
            script.on('message', awaitable.frida_add)
            script.load()
            is_activity_aunched = lambda message: message["type"] == "launch" and message["activity"] == target_activity_name
            awaitable.until(is_activity_aunched)
        except Exception as e:
            raise FridaException("Error while opening activity", e)

        
        max_count = ACTIVITY_LAUNCH_WAIT_TIMEOUT / 0.1
        iteration = 0
        while (self.device.getTopActivity() != target_activity_name):
            time.sleep(0.1)
            if (iteration == max_count):
                Logger.error("Activity not launched")
                return False
            iteration += 1
        Logger.debug("Activity launched")