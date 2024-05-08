import executor.output.Logger as Logger

class PathTracker:
    def __init__(self, target_id, type, path_id, path):
        self.target_id = target_id
        self.path = path
        self.path_id = path_id
        self.type = type

        self.last_step_in_path = -1
        self.current_step_in_path = -1

    def restart_path(self):
        self.last_step_in_path = -1
        self.current_step_in_path = -1
    
    def is_end_reached(self) -> bool:
        if (self.current_step_in_path == len(self.path) - 1):
            return True
    
    def could_progress(self) -> bool:
        """
            Checks if, compared to the last iteration, we could progress in the selected path.

            :return: True if we could progress in the path, False otherwise
        """
        return self.last_step_in_path < self.current_step_in_path
    
    def is_ui_action_required(self) -> bool:
        if (self.path[self.current_step_in_path + 1]["uiInteraction"]!= None):
            return True
        return False
    
    def get_required_on_click(self) -> str:
        return self.path[self.current_step_in_path + 1]["method"]
    
    def is_sys_action_required(self) -> bool:
        if (self.path[self.current_step_in_path + 1]["sysInteraction"]):
            return True
        return False
    
    def get_required_activity_launch(self) -> str:
        interaction = self.path[self.current_step_in_path + 1]["sysInteraction"]
        if (interaction != None and 'type' in interaction and interaction['type'] == "launchActivity"):
            targetActivity = interaction['activityName']
            return targetActivity
        return None

    def update(self, visited_methods) -> None:
        change = False
        for s in range(self.current_step_in_path + 1, len(self.path)):
            step = self.path[s]

            # in case there is a uiInteraction in the path, we want to make sure that we HAVE
            # to perform it. 
            if (step["uiInteraction"] != None):
                if 'method' in step and not step['method'] in visited_methods:
                    break


            if 'method' in step and step['method'] in visited_methods:
                    Logger.debug("Sweet! We could progress to a known location in one of the paths to the target location to step " + str(self.current_step_in_path))
                    self.last_step_in_path = self.current_step_in_path
                    self.current_step_in_path = s
                    change = True
        if change == False:
            self.last_step_in_path = self.current_step_in_path

    def get_current_step(self):
        return self.current_step_in_path
    
    def force_progress(self):
        self.current_step_in_path += 1