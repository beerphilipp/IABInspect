import os
import json
import sys

DEFAULT_RES_FILE = "./missing_packages.json"

def main():
    parameters = sys.argv[1:]
    if (len(parameters) < 1 or len(parameters) > 3):
        print("Usage: python3 get_missing_packages.py <json_file> <result_directory> [<result_file>]")
        print()
        print("The default result file is " + DEFAULT_RES_FILE)
        return
    
    json_file = parameters[0]
    result_directory = parameters[1]
    result_file = parameters[2] if len(parameters) == 3 else DEFAULT_RES_FILE

    result = {}

    with open(json_file, 'r') as f:
        json_data = json.load(f)
        for key in json_data:
             # check if the key file exists
                if (not os.path.isfile(os.path.join(result_directory, key + ".apk"))):
                     result[key] = json_data[key]

    with open(result_file, 'w') as f:
            json.dump(result, f, indent=4)

    print("Stored missing packages in " + result_file)
    return

if __name__ == "__main__":
    main()