const currentActivityName = "${currentActivityName}"
const targetActivityName = "${targetActivityName}"
const data = "${data}"
const extras = ${extras}

Java.perform(function x() {
    Java.choose(currentActivityName, {
        onMatch: function(instance) {
                const targetClass = Java.use(targetActivityName);
                const tClass = targetClass.class
                const intent = Java.use("android.content.Intent").$new(instance, tClass);
                if (extras != null) {
                    for (const [key, value] of Object.entries(extras)) {
                        intent.putExtra(key, value);
                        // TODO: HANDLE PARCELABLES AND BUNDLES AND OTHER TYPES
                    }
                    intent.putExtra("url", "https://www.33website44.com")
                }

                //if (data != null && data != "" && data != "null") {
                //    intent.setData(data);
                //}
                try {
                    instance.startActivity(intent);
                } catch (e) {
                    targetClass.startActivity.overload("android.content.Intent").call(instance, intent);
                }
                
                //instance.startActivity(intent);
                const finishedMessage = {"type": "launch", "activity": targetActivityName}
                send(finishedMessage);
        },
        onComplete: function() {}
    })
})