import os
import json
import sys
import sqlite3

DEFAULT_RES_FILE = "./apks.json"


def read_db_package_names(db_file):
    """
        Reads the SQLite database and selects all apps that have at least 1M installs
    """
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("SELECT appId FROM app WHERE minInstall >= 1000000")
    results = c.fetchall()
    conn.close()
    results = [i[0] for i in results]
    return results

def main():
    parameters = sys.argv[1:]
    if (len(parameters) < 1 or len(parameters) > 3):
        print("Usage: python3 create_apkfiles.py <apk_dir> <sqlite_dir> [<result_file>]")
        print()
        print("This tool creates a json file that contains information about the apk files in the given directory.")
        print("The default result file is " + DEFAULT_RES_FILE)
        return
    
    apk_dir = parameters[0]
    db_dir = parameters[1]
    result_file = parameters[2] if len(parameters) == 3 else DEFAULT_RES_FILE
    
    all_files = os.listdir(apk_dir)

    package_names = read_db_package_names(db_dir)
    print("Found " + str(len(package_names)) + " packages in the database.")

    result = {}
    not_found = 0
    split = 0
    single = 0

    for i in range(0, len(package_names)):
        
        progress = i / len(package_names)
        bar_length = 20
        block = int(round(bar_length * progress))
        text = "\rProgress: [{0}] {1:.1f}%".format("#" * block + "-" * (bar_length - block), progress * 100)
        sys.stdout.write(text)
        sys.stdout.flush()

        package_name = package_names[i]

        results = [i for i in all_files if (i.startswith(package_name + ".split.") and i.endswith(".zip")) or i == package_name + ".apk"]
        if (len(results) > 1):
            result[package_name] = {
                'mode': "MULTIPLE_APKS",
                'split_apks': results,
            }
            split += 1
        elif (len(results) == 1):
            result[package_name] = {
                'mode': 'SINGLE_APK'
            }
            single += 1
        else:
             not_found += 1

    with open(result_file, 'w') as f:
            json.dump(result, f, indent=4)

    print("Found splits: " + str(len(split)))
    print("Found singles: " + str(len(single)))
    print("Total found: " + str(len(split) + len(single)))
    print("Not found: " + str(len(not_found)))
    print("Stored results in " + result_file)
    return

if __name__ == "__main__":
    main()