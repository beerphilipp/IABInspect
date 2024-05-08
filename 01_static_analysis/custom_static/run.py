import concurrent.futures
import subprocess
import sys
import os

def execute_analysis(apk, ram_per_process):
    command = f"java -Xmx{ram_per_process}g -jar ForcedExecStatic-1.0-SNAPSHOT-jar-with-dependencies.jar -apk {apk}"
    print(command)
    try:
        subprocess.run(command, shell=True, check=True, timeout=40*60)  # 40 minutes
        print(f"Command for {apk} executed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command for {apk}: {e}")
    except subprocess.TimeoutExpired:
        print(f"Command for {apk} took too long and was terminated.")

def read_apks_file(apks):
    with open(apks, "r") as file:
        apk_files = file.readlines()
        cleaned_apk_files = []
        for apk in apk_files:
            cleaned = apk.strip()
            if cleaned.startswith("#") or len(cleaned) == 0:
                continue
            cleaned_apk_files.append(cleaned)
    return cleaned_apk_files

def main():
    args = sys.argv[1:]
    if (len(args) != 4):
        print("Usage: python run.py <apks_file> <apk_folder> <parallelism> <ram>")
        sys.exit(1)
    apks = args[0]
    apk_folder = args[1]
    parallelism = int(args[2])
    ram = int(args[3])
    apk_files = read_apks_file(apks)
    ram_per_process = int(ram / parallelism)
    apk_absolute_paths = [os.path.join(apk_folder, apk) for apk in apk_files]

    try:
        with concurrent.futures.ProcessPoolExecutor(parallelism) as executor:
            executor.map(execute_analysis, apk_absolute_paths, [ram_per_process]*len(apk_files))
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()