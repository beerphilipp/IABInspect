import os
import time

from multiprocessing.pool import ThreadPool
from dotenv import load_dotenv
from threading import Lock

from executor.DynamicExecutor import DynamicExecutor

adb_device_lock = Lock()

adb_devices = []
avds = []
emulator_path = None

devices = {}

def get_and_set_available_device():
    while True:
        with adb_device_lock:
            for device, status in devices.items():
                if status == 'AVAILABLE':
                    devices[device] = 'UNAVAILABLE'
                    return device
        time.sleep(1)
        
def release_device(device):
    with adb_device_lock:
        devices[device] = 'AVAILABLE'

def startExecution(package_name, static_result, out_dir):
    device = get_and_set_available_device()
    print(static_result)
    try:
        executor = DynamicExecutor(package_name, static_result, device, out_dir, adb_devices, avds, emulator_path)
        executor.start()
    finally:
        release_device(device)

def main():
    global avds
    global adb_devices
    global emulator_path

    load_dotenv(override=True)
    static_result_dir = os.getenv("STATIC_RESULT_DIR")
    out_dir = os.getenv("OUT_DIR")
    adb_devices = os.getenv("DEVICES").split(",")
    avds_raw = os.getenv("AVDS")
    if avds_raw:
        avds = avds_raw.split(",")
    emulator_path = os.getenv("EMULATOR_PATH")
    for d in adb_devices:
        devices[d] = 'AVAILABLE'

    package_names = [name for name in os.listdir(static_result_dir) if os.path.isdir(os.path.join(static_result_dir, name))]

    #package_names = [package_name for package_name in package_names if package_name.startswith("jp.ne.ambition.googleplay_nizikano2d_glb")]

    print(len(package_names))

    #package_names = [package_name for package_name in package_names if package_name.startswith("com.polysoftstudios.")]
    #package_names = package_names[25:26]
    #print(package_names)

    params = []
    for package_name in package_names:
        params.append((package_name, os.path.join(static_result_dir, package_name, "res.json"), os.path.join(out_dir, package_name)))

    with ThreadPool(len(adb_devices) + 3) as pool:
        for result in pool.starmap(startExecution, params):
            # do sth with the result
            pass

if __name__ == "__main__":
    main()