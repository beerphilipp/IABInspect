import executor.scripts.ScriptUtils as ScriptUtils
from executor.Awaitable import Awaitable

class WebViewInterception:
    def __init__(self, device):
        self.device = device

    def intercept_target_calls(self):
        self.device.frida_session
        jscode = ScriptUtils.readScript("insert-call-id.js", {})
        script = self.device.frida_session.create_script(jscode)
        awaitable = Awaitable()
        script.on('message', awaitable.frida_add)
        script.load()
        waitLambda = lambda x: x['type'] == 'id_insertion' and x["event"] == "hooked"
        #awaitable.waitUntil(waitLambda)       