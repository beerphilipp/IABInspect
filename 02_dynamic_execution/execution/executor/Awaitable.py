import time

import executor.output.Logger as Logger

from threading import Lock

class Awaitable:
    """
        An Awaitable is an abstraction that allows to asynchronously receive events and wait for them.
        Also, it's (hopefully) thread-safe. 
    """

    def __init__(self):
        self.messages = []
        self.condition = None
        self.lock = Lock()
        pass

    def frida_add(self, message, data):
        if "payload" not in message:
            Logger.error(f"Received message without payload: {message}, ignoring it.")
        else:
            self.add(message["payload"])

    def add(self, unpacked_message):
        with self.lock:
            self.messages.append(unpacked_message)
    
    def until(self, condition):
        self.condition = condition

    def reset(self):
        with self.lock:
            oldMessages = self.messages.copy()
            self.messages = []
        return oldMessages
    
    def peek(self):
        return self.messages.copy()

    def wait(self):
        while (True):
            for message in self.messages:
                if (self.condition(message)):
                    self.messages.remove(message)
                    return message
                
    def wait(self, timeout):
        start_time = round(time.time() * 1000)
        while (True):
            for message in self.messages:
                if (self.condition(message)):
                    self.messages.remove(message)
                    return message
            if round(time.time() * 1000) - start_time > timeout:
                return None
    
    def waitUntil(self, condition, runnableTask=None, timeout=None, removePrevious=False):
        if (runnableTask is not None):
            runnableTask.run()
        start_time = time.time()
        while (True):
            for message in self.messages:
                if (condition(message)):
                    if (removePrevious):
                        poppedMessage = self.messages.pop(0)
                        while (poppedMessage != message):
                            poppedMessage = self.messages.pop(0)
                    else:
                        self.messages.remove(message)
                    return message
            if timeout is not None and time.time() - start_time > timeout:
                return None