import executor.scripts.ScriptUtils as ScriptUtils

from executor.tracing.Tracer import Tracer
from executor.Awaitable import Awaitable

class MethodTracer(Tracer):
    def __init__(self, device):
        Tracer.__init__(self, device)

    def start(self, methods):
        self.awaitable, self.script = self.__trace_methods(methods)

    def stop(self):
        if (self.script):
            self.script.unload()

    def get(self):
        if (self.awaitable):
            messages = self.awaitable.reset()
            return list(map(lambda message: message['method'], messages))
        return None

    def reset(self):
        self.get()

    def __trace_methods(self, methods):
        code = ScriptUtils.readScript("trace-functions.js", {"methodSignaturesToTrace": methods})
        script = self.device.frida_session.create_script(code)
        awaitable = Awaitable()
        script.on('message', awaitable.frida_add)
        script.load()
        return (awaitable, script)
    
    def peek(self):
        if (self.awaitable):
            messages = self.awaitable.peek()
            return list(map(lambda message: message['method'], messages))
        return None
