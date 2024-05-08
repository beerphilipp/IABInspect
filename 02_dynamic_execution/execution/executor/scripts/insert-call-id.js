const webViewMethods = [
    "<android.webkit.WebView: void loadUrl(java.lang.String)>",
    "<android.webkit.WebView: void loadUrl(java.lang.String,java.util.Map)>",
    "<android.webkit.WebView: void loadData(java.lang.String,java.lang.String,java.lang.String)>",
    "<android.webkit.WebView: void loadDataWithBaseURL(java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)>",
    "<android.webkit.WebView: void postUrl(java.lang.String,byte[])>"
]

function convertMethodParams(methodParams) {
    for (var i = 0; i < methodParams.length; i++) {
        if (methodParams[i] == "byte[]") {
            methodParams[i] = "[B"
        }
        if (methodParams[i] == "int[]") {
            methodParams[i] = "[I"
        }
        if (methodParams[i] == "long[]") {
            methodParams[i] = "[J"
        }
        // TODO: Add more types as needed
    }
    return methodParams

}
Java.perform(() => {
    for (var methodSignature of webViewMethods) {
        console.log("Overwriting ..." + methodSignature)
        const className = methodSignature.split(": ")[0].split("<")[1]
        const clazz = Java.use(className)
        const methodName = methodSignature.split(" ")[2].split("(")[0]
        const tempMethodParams = convertMethodParams(methodSignature.split("(")[1].split(")")[0].split(","))
        const methodParams = tempMethodParams.length == 1 && tempMethodParams[0] == "" ? [] : tempMethodParams
        clazz[methodName].overload(...methodParams).implementation = function(...params) {
            //const stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
            console.log("HELLO")
            //console.log(stackTrace[3]);
            //var callId = this.__callId;
            //params[0] = params[0] + "#callId=" + callId;
            return clazz[methodName].apply(this, params);
        }
    }
    const finishedMessage = {"type": "id_insertion", "event": "hooked"}
    send(finishedMessage);

});