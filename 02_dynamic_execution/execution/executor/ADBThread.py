import threading
import json
import subprocess
import executor.ADBUtils as ADBUtils
import executor.Awaitable as Awaitable
import executor.output.Logger as Logger

class ADBThread(threading.Thread):
    def __init__(self, package_name, device_serial, awaitable, log_level, log_tag):
        super(ADBThread, self).__init__()
        self.package_name = package_name
        self.device_serial = device_serial
        self.awaitable = awaitable
        self.log_level = log_level
        self.log_tag = log_tag
        self.process = None
        self._stop_event = threading.Event()

    def _get_thread_id(self):
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id
            

    def run(self):
        self._blocking_continuously_notify_log(self.package_name, self.device_serial, self.awaitable, self.log_level, self.log_tag)
            

    def _blocking_continuously_notify_log(self, package_name: str, device_serial: str, awaitable: Awaitable, log_level: str, log_tag: str) -> None:
        """
            Blocks the execution and continuously notifies the awaitable with new log messages of the given level and tag.
            Expects that the log messages are in JSON format.
            If not, the message is ignored.
            
            :param device_serial: The device serial number
            :param awaitable: The awaitable to notify
            :param log_level: The log level
            :param log_tag: The log tag
        """
        ADBUtils.clear_log(device_serial)
        self.process = subprocess.Popen(["adb", "-s", device_serial, "logcat", f"{log_tag}:{log_level}", "*:S", "-v", "raw"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        while not self._stop_event.is_set():
            splits = {}
            for line in self.process.stdout:
                if not line:
                    # process has been terminated
                    break
                if (line.startswith("--------- beginning of main")):
                    continue
                line = line.strip()
                try:
                    if (line.startswith("SPLIT ")):
                        splitLine = line.split(" ")
                        id = splitLine[1]
                        chunk = int(splitLine[2])
                        totalChunk = int(splitLine[3])
                        content = "".join(splitLine[4:])
                        
                        if (chunk == 1):
                            splits[id] = []
                            splits[id].append(content)
                            continue

                        if (chunk != totalChunk):
                            if (len(splits[id]) != chunk - 1):
                                Logger.error(f"Chunk {chunk} is missing for split {id}")
                            splits[id].append(content)
                            continue
                        
                        if (chunk == totalChunk):
                            splits[id].append(content)
                            line = "".join(splits[id])
                            del splits[id]
                    
                    json_line = json.loads(line)
                    if ("33file44-" in str(json_line)):
                        # get the uuid that is after the tag
                        file_id = str(json_line).split("33file44-")[1][0:36]
                        ADBUtils.pull_private_file(device_serial, package_name, file_id)

                    awaitable.add(json_line)
                except json.JSONDecodeError as e:
                    Logger.error(f"Failed to parse the JSON, ignoring it. {e}") 
                    #print(line)   

        if self.process:
            self.process.terminate()
    
    def stop(self):
        self._stop_event.set()
        if self.process:
            self.process.terminate()
