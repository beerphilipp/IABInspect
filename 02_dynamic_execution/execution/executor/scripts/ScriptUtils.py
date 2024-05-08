import os
import json

def readScript(scriptName, params):
        """
        Reads a script from the scripts folder and replaces the params.
        A param is defined as ${paramName} in the script.
        """
        scriptPath = os.path.join(os.path.dirname(__file__), scriptName)
        with open(scriptPath) as f:
            script = f.read()
        
        for key, value in params.items():
            if (type(value) == bool):
                value = str(value).lower()
            if (type(value) == list):
                tempValue = "["
                for item in value:
                    tempValue += "\"" + item + "\","
                tempValue = tempValue[:-1] + "]"
                value = tempValue
            if (type(value) == dict):
                 value = json.dumps(value)
            if (value == None):
                 value = "null"
            script = script.replace("${" + key + "}", value)
        return script