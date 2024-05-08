import pymongo
from pymongo import MongoClient
import sys
import os
import json


def main():
    parameters = sys.argv[1:]
    if (len(parameters) != 1):
        print("Usage: python3 add_results_to_db.py result_directory")
        print()
        print("This tool inserts the result json files into a MongoDB.")
        return    

    result_directory = parameters[0]
    
    client = MongoClient('mongodb://localhost:27017/')
    db = client['webview_prevalence']
    collection = db['2024_01_17']

    for filename in os.listdir(result_directory):
        if filename.endswith(".json"):
            with open(os.path.join(result_directory, filename), 'r') as f:
                json_data = json.load(f)
                result = collection.insert_one(json_data)
                print(f"Document inserted with ID: {result.inserted_id}")

    client.close()


if __name__ == "__main__":
    main()