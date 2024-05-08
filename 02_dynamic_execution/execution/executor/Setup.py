import executor.ADBUtils as ADBUtils
import frida

import executor.output.Logger as Logger

from executor.exceptions.FridaException import FridaException

def setupAndCreateFridaSession(device, instrumentedApkPath, packageName):
    """
        Installs the given APK on the given devices and creates a Frida session.
        This function does not call resume on the frida device for early instrumentation reasons.
        It is the responsibility of the caller to call resume on the frida device. 

        :param device: The device to install the APK on.
        :param instrumentedApkPath: The path to the instrumented APK.
        :param packageName: The package name of the app.
        :return: A tuple containing the frida device, the PID of the app and the Frida session.
        
        raises FridaException: If the Frida server is unavailable or unresponsive on the device.
    """
    
    # install application if not yet installed
    ADBUtils.maybe_install_apk(device.device_name, instrumentedApkPath, packageName)

    # create frida session
    try:
        device = frida.get_device_manager().get_device_matching(lambda d: d.id == device.device_name) 
        pid = device.spawn([packageName])
        fridaSession = device.attach(pid)
    except Exception as e:
        Logger.error(f"Frida server is unavailable/unresponsive on {device.device_name}, error: {e}")
        raise FridaException("Frida server is unavailable/unresponsive on {device.device_name}", e)
    return (device, pid, fridaSession)

def closeFridaSession(fridaSession):
    """
        Closes the given Frida session.
        :param fridaSession: The Frida session to close.
        :raises FridaException: If an error occurs while closing the Frida session.
    """
    try:
        fridaSession.detach()
    except Exception as e:
        raise FridaException("Error while closing Frida session", e)


def writeWebsiteUrlToFile(device, url) -> bool:
    """
        Writes the URL of the website that is forced to load to /sdcard/Download/url.txt.
        
        :return: True if successful, False otherwise.
    """
    return ADBUtils.writeToFile(device.device_name, "/sdcard/Download/url.txt", url)