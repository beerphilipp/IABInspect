import os
import json
import sys

DEFAULT_RES_FILE = "./missing_packages.json"

def main():
    parameters = sys.argv[1:]
    if (len(parameters) < 1 or len(parameters) > 3):
        print("Usage: python3 print_errors.py <result_directory>")
        print()
        print("The default result file is " + DEFAULT_RES_FILE)
        return
    
    result_directory = parameters[0]

    for filename in os.listdir(result_directory):
         if filename.endswith(".json"):
                with open(os.path.join(result_directory, filename), 'r') as f:
                    json_data = json.load(f)
                    if not 'package_name' in json_data:
                         print("ALERT")
                    if 'error' in json_data and json_data['error'] != None and json_data['error'] != "APK_NOT_FOUND":
                        print(json_data['error'])
    return

if __name__ == "__main__":
    main()