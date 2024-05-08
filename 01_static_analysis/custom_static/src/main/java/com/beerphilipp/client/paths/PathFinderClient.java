package com.beerphilipp.client.paths;

import com.beerphilipp.App;
import com.beerphilipp.ClientInfo;
import com.beerphilipp.client.Client;
import com.beerphilipp.client.callgraph.CallGraphClient;
import com.beerphilipp.client.hybridApp.HybridAppClient;

public class PathFinderClient extends Client {

    @Override
    protected void analyze() {

        if (!ClientInfo.getInstance().isFinished(HybridAppClient.class)) {
            new HybridAppClient().start();
        }

        if (App.v().getAppContext().getIsHybridApp()) {
            return;
        }

        if (!ClientInfo.getInstance().isFinished(CallGraphClient.class)) {
            new CallGraphClient().start();
        }

        if (!ClientInfo.getInstance().isFinished(TargetLocationAnalyzer.class)) {
            TargetLocationAnalyzer targetLocationAnalyzer = new TargetLocationAnalyzer();
            targetLocationAnalyzer.start();
        }

        if (!ClientInfo.getInstance().isFinished(PathFinderAnalyzer.class)) {
            PathFinderAnalyzer pathFinderAnalyzer = new PathFinderAnalyzer();
            pathFinderAnalyzer.start();
        }
    }
}
