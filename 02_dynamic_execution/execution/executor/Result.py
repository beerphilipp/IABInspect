import os
import json
import traceback

import executor.Context as Context

from executor.output import Logger

class Result:
    """
        This class is responsible for storing the results of the dynamic execution of an app.

        The results are stored in a JSON file, which is written to the output directory of the app.
    """
    def __init__(self, package_name):
        self.result = {"package_name": package_name, "targets": {}, "exceptions": []}
        self.targets = self.result["targets"]
        pass

    def set_start(self, start):
        self.result["start"] = start
    
    def set_end(self, end):
        self.result["end"] = end

    def add_path_timeout(self, target_id, type, path_id, transition_path, reached_step, api_calls, website_interactions):
        if target_id not in self.targets:
            self.targets[target_id] = {}
        if type not in self.targets[target_id]:
            self.targets[target_id][type] = {}
        if path_id not in self.targets[target_id][type]:
            self.targets[target_id][type][path_id] = {}
        
        self.targets[target_id][type][path_id]["timeout"] = True
        
        if "paths" not in self.targets[target_id][type][path_id]:
            self.targets[target_id][type][path_id]["paths"] = []

        path_dict = {}
        path_dict["path"] = self.path_to_dict_array(transition_path)
        path_dict["apiCalls"] = api_calls
        path_dict["websiteInteractions"] = website_interactions

        self.targets[target_id][type][path_id]["paths"].append(path_dict)
        
        self.write_to_file(self.result["package_name"])
        


    def add_path_explored(self, target_id, type, path_id, transition_path, reached_step, is_triggered, api_calls, website_interactions):
        """
            Adds a path that was explored to the result.

            :param target_id: The id of the target call that was followed
            :param type: The type of the target call that was followed (i.e., resolved or partially resolved)
            :param path_id: The id of the path that was followed
            :param transition_path: The actual transition path
            :param reached_step: The step that was reached in the path
            :param is_triggered: Whether the target location was reached
            :param api_calls: The API calls that were made during the exploration
            :param website_interactions: The website interactions that were made during the exploration
        """
        if target_id not in self.targets:
            self.targets[target_id] =  {} #{"isTriggered": False, "exploredPaths": [], "conincidences": []}
        if type not in self.targets[target_id]:
            self.targets[target_id][type] = {}
        if path_id not in self.targets[target_id][type]:
            self.targets[target_id][type][path_id] = {}
        self.targets[target_id][type][path_id]["reachedStep"] = reached_step
        self.targets[target_id][type][path_id]["isTriggered"] = is_triggered
        if "paths" not in self.targets[target_id][type][path_id]:
            self.targets[target_id][type][path_id]["paths"] = []
        
        path_dict = {}
        path_dict["path"] = self.path_to_dict_array(transition_path)
        path_dict["apiCalls"] = api_calls
        path_dict["websiteInteractions"] = website_interactions

        self.targets[target_id][type][path_id]["paths"].append(path_dict)
        
        if is_triggered:
            self.targets[target_id]["isTriggered"] = True
        self.write_to_file(self.result["package_name"])

    def add_coincidence_explored(self, hit_target_id, followed_target_id, followed_type, followed_path_id, transition_path, api_calls, website_interactions):
        if hit_target_id not in self.targets:
            self.targets[hit_target_id] = {}
        if "coincidences" not in self.targets[hit_target_id]:
            self.targets[hit_target_id]["coincidences"] = []
        
        coincidence_entry = {}
        coincidence_entry["followedTargetId"] = followed_target_id
        coincidence_entry["followedType"] = followed_type
        coincidence_entry["followedPath"] = followed_path_id
        coincidence_entry["path"] = self.path_to_dict_array(transition_path)
        coincidence_entry["apiCalls"] = api_calls
        coincidence_entry["websiteInteractions"] = website_interactions
        self.targets[hit_target_id]["coincidences"].append(coincidence_entry)

        self.targets[hit_target_id]["isTriggered"] = True
    
    def add_general_exception(self, type, exception):
        self.result['exceptions'].append({"type": type, "description": str(exception)})
        self.write_to_file(self.result["package_name"])

    def add_exception(self, target_id, type, path_id, exception):
        if (target_id not in self.targets):
            self.targets[target_id] = {}
        if (type not in self.targets[target_id]):
            self.targets[target_id][type] = {}
        if (path_id not in self.targets[target_id][type]):
            self.targets[target_id][type][path_id] = {}
        self.targets[target_id][type][path_id]["exception"] = {'description': str(exception), 'stacktrace': traceback.format_exc()}
        self.targets[target_id][type][path_id]
        
        self.result['exceptions'].append({"type": "path_exception", "description": str(exception), 'stacktrace': traceback.format_exc()})

    def path_skipped(self, target_id, type, path_id):
        if target_id not in self.targets:
            self.targets[target_id] = {}
        if type not in self.targets[target_id]:
            self.targets[target_id][type] = {}
        if path_id not in self.targets[target_id][type]:
            self.targets[target_id][type][path_id] = {}
        self.targets[target_id][type][path_id]["skipped"] = True

    def write_to_file(self, package_name) -> None:
        """
            Writes the result of the dynamic execution to a file.

            :param packageName: The package name of the app currently being executed.
        """
        Logger.debug("Writing result to file")
        output_path = os.path.join(Context.outputDir, package_name + ".json")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as file:
            json.dump(self.result, file, indent=4)


    def path_to_dict_array(self, path):
        transitions = []
        for transition in path:
            dict = {}
            dict["fromScreen"] = transition.fromScreen.toDict() if transition.fromScreen != None else None
            dict["toScreen"] = transition.toScreen.toDict() if transition.toScreen != None else None
            actions = []
            for action in transition.transitions:
                actions.append(action.toDict())
            dict["actions"] = actions
            transitions.append(dict)
        return transitions
