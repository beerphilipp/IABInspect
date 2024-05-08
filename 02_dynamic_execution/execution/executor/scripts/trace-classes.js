const ignoreClasses = ["android.", "androidx", "java.", "javax.", "dalvik.", "com.android.", "kotlin.", "com.google.firebase.", "com.google.android.gms."];
const classesOfInterest = ${classesToTrace};

Java.perform(function x() {
    for (var className of classesOfInterest) {
        const queryString = className + "!*/su"
        const methodResult = Java.enumerateMethods(queryString);
        const returnedClasses = methodResult.flatMap(loaderData =>
            loaderData.classes).filter(clazz => !ignoreClasses.some(ignoreClass => clazz.name.startsWith(ignoreClass))).filter(clazz => clazz.methods);
            returnedClasses.forEach( clazz => {
            try {
                var targetClass = Java.use(clazz.name);
                const methods = clazz.methods;
                methods.forEach(methodName => {
                    try {
                        console.log("Tracing method " + methodName)
                        targetClass[methodName.split("(")[0]].implementation = function(...parameters) { 

                            // format the method as in: <com.frenchtoday.epubreader.HomeActivity: void onClickHandler(android.view.View)>
                            const _methodSignature = "<" + clazz.name + ": " + methodName.split(": ")[1] + " " + methodName.split(": ")[0] + ">";
                            const message = {type: "tracing", "event": "method_entered", "class": clazz.name, "method": _methodSignature}
                            send(message)
                            return targetClass[methodName.split("(")[0]].apply(this, parameters);
                        }
                    } catch (e) { }
                });
            }
            catch (e) { }
        })
    }
});