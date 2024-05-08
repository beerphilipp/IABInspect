from executor.exceptions.DeviceException import DeviceException
from executor.exceptions.UnrecoverableException import UnrecoverableException

import executor.output.Logger as Logger
import executor.ADBUtils as ADBUtils
import executor.ui.UIUtils as UIUtils
import executor.EmulatorUtils as EmulatorUtils
import uiautomator2

class Device:

    device_name = None

    def __init__(self, device_name, package_name):
        self.device_name = device_name
        self.frida_session = None
        self.package_name = package_name
        self.is_emulator = ADBUtils.is_emulator(device_name)
        self.emulator_restart_count = 0
    
    def update_frida_session(self, frida_session):
        self.frida_session = frida_session

    def getTopActivity(self):
        return ADBUtils.get_top_activity(self.device_name)
    
    def getUI(self):
        return UIUtils.get_xml_of_screen(self.device_name)
    
    def is_online(self):
        return ADBUtils.is_device_online(self.device_name)
    
    def recover(self, get_ready=True, try_no=0):
        """
            Recovers the device in case of an unrecoverable crash.
        """
        if try_no > 3:
            raise UnrecoverableException("Could not recover device " + self.device_name + ". Please restart the device manually.")

        Logger.info(f"Recovering device {self.device_name} (try {try_no + 1} of 3)")
        is_restarted = ADBUtils.blocking_restart_device(self.device_name, timeout=60)

        if not is_restarted:
            if self.is_emulator:
                is_booted = EmulatorUtils.blocking_restart_emulator(self.device_name, 90) # 90 seconds timeout
                if try_no == 0:
                    self.emulator_restart_count += 1
                is_restarted = ADBUtils.blocking_restart_device(self.device_name, timeout=60) # we have to ADB restart after restarting the emulator as well
                if (not is_restarted):
                    self.recover(get_ready=get_ready, try_no=try_no + 1)
            else:
                self.recover(get_ready=get_ready, try_no=try_no + 1)
        if get_ready:
            self.get_ready()

    def go_home(self):
        ADBUtils.goto_home(self.device_name)

    def get_ready(self):
        """
            Gets the device ready for dynamic execution.
            This function assumes the Web Server and Frida to be installed on the device. 
        """
        Logger.info("Getting device " + self.device_name + " ready for dynamic execution...")
        if (not ADBUtils.is_device_online(self.device_name)):
            self.recover(get_ready=False)

        # disable animations
        success = ADBUtils.disable_animations(self.device_name)

        # start the web server
        success = success and ADBUtils.start_web_server(self.device_name)
        
        # start frida if not already started
        success = success and ADBUtils.maybe_start_frida_server(self.device_name)

        success = success and ADBUtils.set_logcat_size(self.device_name, 256)

        success = success and ADBUtils.goto_home(self.device_name)

        # connect to uiautomator server
        d = uiautomator2.connect(self.device_name)
        d.dump_hierarchy() # we do this to force the connection

        if not success:
            raise UnrecoverableException("Could not get device " + self.device_name + " ready for dynamic execution. Please restart the device manually.")