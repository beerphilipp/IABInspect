Java.perform(function () {
    const activity = Java.use('android.webkit.WebView');
    activity.loadUrl.overload('java.lang.String').implementation = function (str) {
        // Your custom logic to reopen the app
        const stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
        console.log(stackTrace[3]);
        this.loadUrl(str);
    };
});