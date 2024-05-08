import os
import subprocess
import json
import base64
import json
import time

import executor.output.Logger as Logger
from executor.exceptions.DeviceException import DeviceException
import executor.Context as Context

from executor.Awaitable import Awaitable

WV_TRACE_TAG = "33WV_INSPECT44"

def get_top_package_name(device):
    """
    Get the top package name of a device
    :param device: The device serial number
    :return: The top package name
    """
    result = subprocess.run(["adb", "-s", device, "shell", "dumpsys", "activity", "activities", "|", "grep", "topResumedActivity"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        lines = result.stdout.decode("utf-8").splitlines()
        if (len(lines) != 1):
            Logger.error("Unexpected output from dumpsys activity activities: " + str(lines))
        package_name_and_activity = lines[0].split("topResumedActivity")[1].split(" ")[2]
        package_name = package_name_and_activity.split("/")[0]
        return package_name
    return None


def get_top_activity(device):
    """
    Get the top activity of a device
    :param device: The device serial number
    :return: The top activity
    """
    result = subprocess.run(["adb", "-s", device, "shell", "dumpsys", "activity", "activities", "|", "grep", "topResumedActivity"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        lines = result.stdout.decode("utf-8").splitlines()
        if (len(lines) != 1):
            Logger.error("Unexpected output from dumpsys activity activities: " + str(lines))
        #package_name_and_activity = lines[0].split("topResumedActivity")[1].split(" ")[2]
        #package_name = package_name_and_activity.split("/")[0]
        #activity_name = package_name_and_activity.split("/")[1][:-1]
        #return package_name + "" + activity_name
        activityName = lines[0].split("topResumedActivity")[1].split(" ")[2].split("/")[1][:-1]
        if (activityName.startswith(".")):
            # the activity name could also be of this form: com.gaurgrow.distancelandareameasure/.gps.activities.LanguageActivity
            # in this case, we need to add the firt part as well
            package = lines[0].split("topResumedActivity")[1].split(" ")[2].split("/")[0]
            return package + activityName

        return activityName
    return None

def maybe_uninstall_apk(serial, package_name) -> None:
    if (is_package_installed(serial, package_name)):
        uninstall_apk(serial, package_name)


def uninstall_apk(serial, package_name) -> None:
    """
    Uninstalls the given application on the given device.
    :param serial: The device serial number
    :param package_name: The package name
    """
    result = subprocess.run(["adb", "-s", serial, "uninstall", package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        Logger.error("Failed to uninstall APK: " + str(result.stderr.decode("utf-8")))

def is_package_installed(serial, package_name):
    result = subprocess.run(["adb", "-s", serial, "shell", "pm", "list", "packages", "|", "grep", "-x", "package:" + package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True
    else:
        return False


def maybe_install_apk(serial, apk, package_name) -> None:
    """
        Installs the given application on the given device if it is not yet installed.
        :param serial: The device serial number
        :param apk: The path to the APK
        :return: True if the installation was successful
    """
    if (not is_package_installed(serial, package_name)):
        install_apk(serial, apk)

def install_apk(device, apk):
    """
    Install an apk on a device
    :param device: The device serial number
    :param apk: The apk path
    :return: True if the installation was successful, False otherwise
    """
    result = subprocess.run(["adb", "-s", device, "install", "-g", apk], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True
    else:
        lines = result.stdout.decode("utf-8").splitlines()
        Logger.error("Failed to install APK: " + str(lines) + " " + str(result.stderr.decode("utf-8")))
        return False
    
def disable_animations(device):
    """
        Disables animations on the device.
        This is useful to (1) speed up the execution and (2) allow us to more easily determine the screens that are being displayed.

        :param device: The device serial number.
        :return: Whether the process was successful.
    """
    result1 = subprocess.run(["adb", "-s", device, "shell", "settings", "put", "global", "window_animation_scale", "0.0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result2 = subprocess.run(["adb", "-s", device, "shell", "settings", "put", "global", "transition_animation_scale", "0.0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result3 = subprocess.run(["adb", "-s", device, "shell", "settings", "put", "global", "animator_duration_scale", "0.0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result1.returncode != 0 or result2.returncode != 0 or result3.returncode != 0:
        Logger.error("Failed to disable animations.")
        Logger.error(result1.stderr.decode("utf-8"))
        return False
    return True

    

def clear_log(device_serial):
    """
        Clears the log of a device.

        :param device_serial: The device serial number.
        :return: True if the clearing was successful, False otherwise.
    """
    result = subprocess.run(["adb", "-s", device_serial, "logcat", "-c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True
    else:
        return False

def writeToFile(device, file, content):
    """
        Writes the given content to the given file on the given device.
        If the file does not exist, the file is created.
        If the file exists, the file is overwritten.

        :param device: The device serial number.
        :param file: The path to the file.
        :param content: The content of the file.
        :return: Whether the process was successful.
    """
    # to escape special characters, we write the file in base64 and then decode it
    base64Content = base64.b64encode(content.encode()).decode()
    base64File = file + ".base64"
    result = subprocess.run(["adb", "-s", device, "shell", "echo", base64Content, ">", base64File, "&&", "base64", "-d", base64File, ">", file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def start_web_server(serial):
    """
    Starts a web server on the device
    :param serial: The device serial number
    :return: True if the web server was started successfully, False otherwise
    """
    result = subprocess.run(["adb", "-s", serial, "shell", "am", "start-foreground-service", "com.beerphilipp.wvinjection.webserver/com.beerphilipp.wvinjection.webserver.ServerService"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True
    else:
        Logger.error("Failed to start the web server.")
        raise Exception("Failed to start the web server")
    

def maybe_start_frida_server(serial):
    """
        Starts the Frida server on the device if it is not running.
        If a pyhsical device is used, the function just returns since Frida is managed by Magisk.
    """
    if (not is_emulator(serial)):
        return True
        subprocess.run(["adb", "-s", serial, "root"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = subprocess.run(["adb", "-s", serial, "shell", "netstat", "-tunlp", "|", "awk", "'/frida-server/ {print $7}'", "|", "cut", "-d", "'/'", "-f1", "|", "head", "-n", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        result = subprocess.run(["adb", "-s", serial, "shell", "su", "-c", "netstat", "-tunlp", "|", "awk", "'/frida-server/ {print $7}'", "|", "cut", "-d", "'/'", "-f1", "|", "head", "-n", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        Logger.error("Failed to check if Frida is running")
        return False
    
    if result.stdout.decode("utf-8").strip() == "":
        return start_frida_server(serial)
    
    return True
    
def start_frida_server(serial):
    if (is_emulator(serial)):
        subprocess.run(["adb", "-s", serial, "root"])
        result = subprocess.Popen(["adb", "-s", serial, "shell", "/data/local/tmp/frida-server &"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)
        result.kill()
        return True
        # we don't want to wait, so we use Popen
    

def close_clear_app(serial, package_name):
    """
        If we use adb shell pm clear <package_name>, we also clear the permissions and we don't want that.

    """
    result = subprocess.run(["adb", "-s", serial, "shell", "am", "force-stop", package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #result = subprocess.run(["adb", "-s", serial, "shell", "pm", "clear", package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True
    else:
        Logger.error("Failed to close and clear the app.")
        Logger.error(result.stderr.decode("utf-8"))
        return False
    
def is_emulator(serial):
    return serial.startswith("emulator-")


def check_app_crash(serial, package_name):
    """
    """
    try:
        result = subprocess.run(["adb", "-s", serial, "logcat", "-b", "crash", "-d"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        subprocess.run(["adb", "-s", serial, "logcat", "-b", "crash", "-c"], timeout=10)
        if result.stdout.decode("utf-8").find(package_name) != -1:
            return True
        
        if (get_top_activity(serial) == "com.google.android.apps.nexuslauncher.NexusLauncherActivity"):
            return True

        return False
    except subprocess.TimeoutExpired:
        Logger.error("Timeout while checking for app crash.")
        return True
    

def set_logcat_size(serial, size):
    """
        Sets the logcat size to the given size.
        :param serial: The device serial number
        :param size: The size in MB
        :return: True if the size was set successfully, False otherwise
    """
    result = subprocess.run(["adb", "-s", serial, "shell", "logcat", "-G", str(size) + "M"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True
    else:
        Logger.error("Failed to set the logcat size.")
        return False
    
def goto_home(serial):
    """
        Goes to the home screen of the device.
        :param serial: The device serial number
        :return: True if the process was successful, False otherwise
    """
    result = subprocess.run(["adb", "-s", serial, "shell", "input", "keyevent", "KEYCODE_HOME"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True
    else:
        Logger.error("Failed to go to the home screen.")
        return False
    
def pull_private_file(serial, package_name, file_name, count=0):
    if not os.path.exists(Context.outputDir):
        os.makedirs(Context.outputDir)

    result = subprocess.run(["adb", "-s", serial, "pull", f"data/data/{package_name}/files/{file_name}", Context.outputDir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return True
    else:
        Logger.error("Failed to pull the file, will retry? " + str(count < 5) + " " + str(result.stderr.decode("utf-8")))
        if count < 5:
            return pull_private_file(serial, package_name, file_name, count + 1)
        return False

def is_device_online(serial) -> bool:
    result = subprocess.run(["adb", "-s", serial, "shell", "getprop", "sys.boot_completed"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0 and result.stdout.decode("utf-8").strip() == "1":
        return True
    return False

def wait_until_device_booted(serial, timeout=60) -> bool:
    start = time.time()
    while True:
        if time.time() - start > timeout:
            return False
        device_online = is_device_online(serial)
        if device_online:
            return True


def blocking_restart_device(serial, timeout=60) -> bool:
    result = subprocess.run(["adb", "-s", serial, "reboot"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (result.returncode != 0):
        return False
    is_booted = wait_until_device_booted(serial, timeout=timeout)
    if (is_booted):
        time.sleep(2)
        # we wait two more seconds
    return is_booted