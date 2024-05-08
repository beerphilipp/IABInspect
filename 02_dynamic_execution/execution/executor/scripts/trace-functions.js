/*
* This script is used to trace the execution of a set of methods.
* The methods to trace are defined in the methodSignaturesToTrace variable.
* Each method to trace is expected to be in the form: "<com.example.Class: void methodName(param1,param2)>"
* The script will hook each method and send a message when the method is entered.
* The message is of the form:
* { 
*   "type": "tracing", 
*   "event": "method_entered", 
*   "class": "com.example.Class", 
*   "method": "<com.example.Class: void methodName()>" 
* }
*/

const methodSignatures = ${methodSignaturesToTrace};

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

Java.perform(function x() {
    console.log("To trace: " + methodSignatures)
    for (var methodSignature of methodSignatures) {
        const className = methodSignature.split(": ")[0].split("<")[1]
        const clazz = Java.use(className)
        const tempMethodName = methodSignature.split(" ")[2].split("(")[0]
        const tempMethodParams = convertMethodParams(methodSignature.split("(")[1].split(")")[0].split(","))
        const methodParams = tempMethodParams.length == 1 && tempMethodParams[0] == "" ? [] : tempMethodParams
        const _signature = methodSignature
        const methodName = (tempMethodName == "<init>") ? "$init" : tempMethodName // If we want to overwrite the constructor, Frida uses the $init name for constructors.
        try {
            clazz[methodName].overload(...methodParams).implementation = function(...params) {
                const message = {type: "tracing", "event": "method_entered", "class": className, "method": _signature}
                send(message);
                if (methodName == "$init") {
                    // Constructors should be hooked differently, see https://github.com/iddoeldor/frida-snippets#hook-constructor)
                    return this.$init(...params)
                } else {
                    return clazz[methodName].apply(this, params);
                }
            }
        } catch (e) {
            console.error("Error hooking method: " + methodSignature + " - " + e);
        }
    }
    console.log("Tracing setup complete.")
});