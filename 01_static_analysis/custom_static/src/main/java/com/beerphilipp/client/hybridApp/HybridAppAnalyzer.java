package com.beerphilipp.client.hybridApp;

import com.beerphilipp.ClientInfo;
import com.beerphilipp.client.Analyzer;
import com.beerphilipp.util.ApkUtil;

public class HybridAppAnalyzer extends Analyzer {

        @Override
        public void analyze() {
            if (ClientInfo.getInstance().isFinished(HybridAppAnalyzer.class)) {
                return;
            }

            boolean isHybridApp = ApkUtil.isHybridApp(appContext.getAbsolutePath());
            //appContext.setIsHybridApp(isHybridApp);
            appContext.setIsHybridApp(false);
            // If this is a hybrid app, we need to do some additional analysis
        }
}
