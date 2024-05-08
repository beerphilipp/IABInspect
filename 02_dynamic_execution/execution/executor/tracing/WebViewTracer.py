from executor.ADBThread import ADBThread

import executor.ADBUtils as ADBUtils

from executor.tracing.Tracer import Tracer
from executor.Awaitable import Awaitable
import executor.output.Logger as Logger

class WebViewTracer(Tracer):

    def __init__(self, device):
        Tracer.__init__(self, device)
        self.thread = None

    def start(self):
        if (self.thread == None):
            self.awaitable = Awaitable()
            self.thread = ADBThread(self.device.package_name, self.device.device_name, self.awaitable, "I", "33WV_INSPECT44")
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
            target_calls = [message['id'] for message in messages if message['type'] == 'targetCall']
            return target_calls
        return None
    
    def peek(self):
        if (self.awaitable):
            messages = self.awaitable.peek()
            target_calls = [message['id'] for message in messages if message['type'] == 'targetCall']
            return target_calls
        return None