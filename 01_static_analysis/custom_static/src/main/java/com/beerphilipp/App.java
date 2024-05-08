package com.beerphilipp;

import lombok.Getter;
import soot.G;


public class App {

    private static App instance;

    @Getter
    private AppContext appContext;

    public static App v() {
        if (instance == null) {
            instance = new App();
        }
        return instance;
    }

    public static void reset() {
        instance = null;
        G.reset();
        ClientInfo.reset();
    }

    public void setApkPath(String apkPath) {
        appContext = AppContext.getInstance2(apkPath);
    }
}
