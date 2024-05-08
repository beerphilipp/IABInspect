package com.beerphilipp.client.hybridApp;

import com.beerphilipp.ClientInfo;
import com.beerphilipp.client.Client;

/**
 * Checks if the app is a hybrid app.
 */
public class HybridAppClient extends Client {

    @Override
    protected void analyze() {
        if (ClientInfo.getInstance().isFinished(HybridAppClient.class)) {
            return;
        }

        HybridAppAnalyzer hybridAppAnalyzer = new HybridAppAnalyzer();
        hybridAppAnalyzer.start();

    }
}
