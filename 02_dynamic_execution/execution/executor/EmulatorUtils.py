import subprocess

import executor.Context as Context
import executor.ADBUtils as ADBUtils
import executor.output.Logger as Logger

from executor.exceptions.UnrecoverableException import UnrecoverableException

def blocking_restart_emulator(serial, timeout=90):
    """
        Restarts the emulator.
    """
    Logger.info("Restarting emulator " + serial + "...")
    devices = Context.devices
    avds = Context.avds
    emulator_path = Context.emulator_path

    avd = None
    for i in range(0, len(devices)):
        if devices[i] == serial:
            avd = avds[i]
            break

    subprocess.run(["pkill", "-f", avd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    subprocess.Popen([emulator_path, "-avd", avd, "-writable-system"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    # we do not care if this process keeps running. In fact, it should keep running even when this python script is termianted
    is_booted = ADBUtils.wait_until_device_booted(serial, timeout)
    return is_booted
    



