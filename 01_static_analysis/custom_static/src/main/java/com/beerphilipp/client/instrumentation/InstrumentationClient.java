package com.beerphilipp.client.instrumentation;

import com.beerphilipp.*;
import com.beerphilipp.client.Client;
import com.beerphilipp.client.instrumentation.branches.BranchConditionSet;
import com.beerphilipp.client.paths.PathFinderClient;
import com.beerphilipp.util.SetupUtil;
import soot.G;

import java.util.Map;

/**
 * Instruments the app and writes the instrumented apk to the file system.
 */
public class InstrumentationClient extends Client {

    @Override
    protected void analyze() {
        if (!ClientInfo.getInstance().isFinished(PathFinderClient.class)) {
            new PathFinderClient().start();
        }

        if (App.v().getAppContext().getIsHybridApp()) {
            return;
        }

        if (App.v().getAppContext().isOnlyContainsExcludedMethods()) {
            return;
        }

        // Setup Soot
        G.reset();
        AppContext appContext = App.v().getAppContext();
        SetupUtil.setupSootInstrumentation(appContext);
        //SetupUtil.setupSoot(appContext, Config.androidJarPath);

        // update all statement identities
        for (StatementIdentity statementIdentity : appContext.getStatementIdentities()) {
            statementIdentity.updateIdentity();
        }

        Instrumenter instrumenter = new Instrumenter();
        instrumenter.start();

        ApkWriter apkWriter = new ApkWriter();
        apkWriter.start();

    }
}
