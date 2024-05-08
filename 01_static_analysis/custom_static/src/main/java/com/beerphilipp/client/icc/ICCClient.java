package com.beerphilipp.client.icc;

import com.beerphilipp.Config;
import com.beerphilipp.client.Client;

public class ICCClient extends Client {

    @Override
    protected void analyze() {
        ICCAnalyzer iccAnalyzer = new ICCAnalyzer();
        iccAnalyzer.start();
    }
}
