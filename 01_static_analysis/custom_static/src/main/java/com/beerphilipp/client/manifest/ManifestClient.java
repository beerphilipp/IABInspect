package com.beerphilipp.client.manifest;

import com.beerphilipp.App;
import com.beerphilipp.ClientInfo;
import com.beerphilipp.client.Client;
import com.beerphilipp.util.SetupUtil;
import soot.Scene;
import soot.SootClass;

public class ManifestClient extends Client {

        @Override
        protected void analyze() {
            if (ClientInfo.getInstance().isFinished(ManifestClient.class)) {
                return;
            }

            SetupUtil.setupSootFast();

            if (App.v().getAppContext().getApplicationClassNames().isEmpty()) {
                for (SootClass sc : Scene.v().getApplicationClasses()) {
                    App.v().getAppContext().addApplicationClassName(sc.getName());
                }
            }

            ManifestAnalyzer manifestAnalyzer = new ManifestAnalyzer();
            manifestAnalyzer.start();

        }
}
