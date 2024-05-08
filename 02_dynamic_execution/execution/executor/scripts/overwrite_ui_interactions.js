// This script overwrites all ui interaction functions in the app.
// It sends a message to the server when an onClick function is called.
// This message contains the class name and the resource id of the clicked view.
// The script also sends a message when it has finished overwriting all onClick functions.

const clickFunctions = [
    /*View.OnClickListener*/"onClick(android.view.View): void",
    /*AdapterView.OnItemClickListener*/"onItemClick(android.widget.AdapterView, android.view.View, int, long): void",
    /*View.OnTouchListener*/"onTouch(android.view.View,android.view.MotionEvent): void",
]

/*
* Example return value:
* {
*   "com.google.android.gms.internal.ads.rc0":
*       ["onClick(android.view.View): void"],
*   "com.google.android.gms.internal.ads.qc0":
*       ["onClick(android.view.View): void"],
* }
*/
function getAllUIClickClassesMethods() {
    var clickClasses = {};
    for (var clickFunction of clickFunctions) {
        const methodResult = Java.enumerateMethods("*!" + clickFunction + "*/su"); // s: Include method signatures in the output, u: Include only user-defined classes, ignoring system classes.
        return methodResult;
    }
    return clickClasses;
}

Java.perform(function () {
    var loaderClassesAndMethods = getAllUIClickClassesMethods();
    for (var element of loaderClassesAndMethods) {
        var clazzLoader = element['loader'];
        Java.classFactory.loader = clazzLoader;
        var clazzes = element['classes'];
        for (var clazzElement of clazzes) {
            var clazz = clazzElement['name'];
            var methods = clazzElement['methods'];
            var targetClass  = Java.use(clazz);
            for (var methodSignature of methods) {
                var methodName = methodSignature.split("(")[0];
                var returnValue = methodSignature.split(": ")[1];
                var params = methodSignature.split("(")[1].split(")")[0].replace(/\s/g, "");
                const methodParams = params.length == 1 && params[0] == "" ? [] : params
                
                if (clazz.startsWith("androidx.appcompat.app.AppCompatViewInflater$DeclaredOnClickListener")) {
                    // If the onClickListener is in the androidx.appcompat.app.AppCompatViewInflater$DeclaredOnClickListener class, we need to handle it differently.
                    // The "target" class is lazy fetched. We need to call the resolveMethod() function to get the actual function.
                    console.log("Handling androidx.appcompat.app.AppCompatViewInflater$DeclaredOnClickListener");
                    console.log("Method: " + methodName);
                    console.log("Params: " + params);
                    targetClass.onClick.overload('android.view.View').implementation = function (view) {
                        const _resourceIdNumber = view.getId();
                        var _resourceId = null;
                        if (_resourceIdNumber != -1) {
                            // A resource id of -1 means that the view has no id.
                            _resourceId = view.getResources().getResourceEntryName(_resourceIdNumber);
                        }

                        this.resolveMethod(this.mHostView.value.getContext());
                        const _methodSignature = "<" + this.mResolvedMethod.value.getDeclaringClass().getName() + ": " + this.mResolvedMethod.value.getReturnType() + " " + this.mResolvedMethod.value.getName() + "(" + this.mResolvedMethod.value.getParameterTypes().map(type => type.getName()) + ")>";
                        const _msg = {"type": "uiclick", "event": "click", "method": _methodSignature, "resourceId": _resourceId, "resourceIdNumber": _resourceIdNumber};
                        send(_msg);
                    }
                } else {
                    console.log("Method: " + methodName);
                    console.log("Params: " + params);
                    targetClass[methodName].overload('android.view.View').implementation = function(...parameters) {
                        const th = Java.use("java.lang.Throwable").$new();
                        // It seems like Frida has a problem with anonymous classes somehow (it somehow overwrites them ¯\_(ツ)_/¯).
                        const realClassName = th.getStackTrace()[0].getClassName() //console.log(th.getStackTrace()[0])
                        const view = parameters[0];
                        const _resourceIdNumber = view.getId();
                        var _resourceId = null;
                        if (_resourceIdNumber != -1) {
                            _resourceId = view.getResources().getResourceEntryName(_resourceIdNumber);
                        }
                        const _methodSignature = "<" + realClassName + ": " + returnValue + " " + methodName + "(" + params + ")>";
                        const _msg = {"type": "uiclick", "event": "click", "method": _methodSignature, "resourceId": _resourceId, "resourceIdNumber": _resourceIdNumber};
                        send(_msg);
                    }
                }
            }
        }

        

    }
    const finishedMessage = {"type": "uiclick", "event": "overwrite_finished"};
    send(finishedMessage);
});