Java.perform(function () {
    const queryString = + "*!*/su"
        const methodResult = Java.enumerateMethods(queryString);
    print(methodResult)
    const activity = Java.use('android.app.Activity');
    activity.class.getDeclaredMethods().forEach(function (method) {
        console.log(method.toString());
    });

    activity.onCreate.implementation = function (bundle) {
        // Your custom logic to reopen the app
        console.log('App reopened!');
        this.onCreate(bundle);
    };
});