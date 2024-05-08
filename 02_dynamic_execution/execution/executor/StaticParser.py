import os
import json
import pathlib

import executor.output.Logger as Logger

class StaticParser:
    """
        This class is responsible for parsing and reading the static analysis results of an application.
    """

    def __init__(self, static_result: str) -> None:
        """
            Initializes the StaticParser.

            :param static_result: The path to the static analysis results file.
        """
        self.static_result_path = static_result
        self.static_dict = self.open_static_result_file(static_result)

    def get_target_id(self, target) -> list:
        return target['uuid']

    def get_action_targets(self) -> list:
        return self.static_dict['actionTargets']
    
    def get_resolved_paths(self, target) -> list:
        return target['resolvedPaths']
    
    def get_partially_resolved_paths(self, target) -> list:
        return target['partiallyResolvedPaths']

    def read_exception(self) -> str:
        """
            Returns the exception message based on the static analysis results.

            :return: The exception message.
        """
        return self.static_dict['exception'] if 'exception' in self.static_dict else None

    def read_instrumented_apk_path(self, relative) -> str:
        """
            Returns the path to the instrumented APK based on the static analysis results.

            Since the file system of the machine running the static analysis may differ from the file system of the machine running the dynamic analysis,
            setting the relative parameter to True will ignore the path defined in the static analysis results file and instead return the actual path to the APK file.

            :param relative: Whether to return the actual path to the APK file or the path defined in the static analysis results file.
            :return: The path to the instrumented APK.
        """
        path = self.static_dict['instrumentedApkPath']
        if (path == None):
            return None
        if (not relative):
            return path
        
        apk_name = self.static_dict['instrumentedApkPath'].split("/")[-1]

        parent_directory = pathlib.Path(self.static_result_path).parent.absolute()
        new_path = os.path.join(parent_directory, apk_name)
        return new_path   

    def read_activities(self) -> list[str]:
        """
            Returns the list of activities in the application based on the static analysis results.

            :return: The list of activities in the application.
        """
        return self.static_dict['activities'] if 'activities' in self.static_dict else []

    def read_package_name(self) -> str:
        """
            Returns the package name of the application based on the static analysis results.

            :return: The package name of the application.
        """
        return self.static_dict['packageName']

    def open_static_result_file(self, static_res) -> dict:
        """
            Parses the given file as a JSON file and returns the result.

            :param static_res: The path to the file to parse.
            :return: The parsed JSON file as a dict.
        """
        try:
            with open(static_res, "r") as f:
                data = json.load(f)
        except FileNotFoundError as e:
            Logger.error(f"File {static_res} not found.")
            raise e
        return data

    def read_intent_data_extra_for_activity(self, activity_name) -> tuple[str, dict[str, str]]:
        """
            Returns the possible intent data and extras for the given activity based on the static analysis results.

            The output is a taple of the form (data, extras), where data is the intent data and extras is a dictionary with the possible extras, 
            where the key is the extra name and the value is the extra type.

            :param activityName: The name of the activity for which we want to get the possible intents.
            :return: A tuple with the intent data and the possible extras.
        """
        intents = {}
        activities = self.static_dict['activities']
        activity = next((activity for activity in activities if activity['name'] == activity_name), None)
        if (activity == None):
            Logger.error(f"Activity {activity_name} not found.")
            raise Exception(f"Activity {activity_name} not found.")
        for extra in activity['intent']['extras']:
            extra_name = extra['name']
            extra_type = extra['type']
            intents[extra_name] = extra_type
        data = activity['intent']['data']
        return (data, intents)