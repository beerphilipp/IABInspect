from executor.ADBThread import ADBThread

import executor.ADBUtils as ADBUtils

import executor.output.Logger as Logger
from executor.tracing.Tracer import Tracer
from executor.Awaitable import Awaitable

class WebsiteTracer(Tracer):

    def __init__(self, device):
        Tracer.__init__(self, device)
        self.thread = None

    def start(self):
        if (self.thread == None):
            self.awaitable = Awaitable()
            self.thread = ADBThread(self.device.package_name, self.device.device_name, self.awaitable, "I", "33WV_WEBSITE44")
            self.thread.start()
        self.reset()
        pass

    def stop(self):
        self.awaitable = None
        if (self.thread):
            self.thread.stop()
            self.thread.join()

    def reset(self):
        self.get()

    def get(self):
        if (self.awaitable):
            messages = self.awaitable.reset()
            return messages
        return None
    
    def peek(self):
        if (self.awaitable):
            messages = self.awaitable.peek()
            return messages
        return None