package com.beerphilipp.client;

import com.beerphilipp.AppContext;
import com.beerphilipp.App;
import com.beerphilipp.ClientInfo;
import com.beerphilipp.util.OutputUtil;

/**
 * Base class for all analyzers.
 *
 * An analyzer performs a specific analysis on a given app.
 * Its start method is called by the client that uses it.
 *
 * Subclasses of this class should implement only the analyze method.
 */
public abstract class Analyzer {

    protected AppContext appContext = App.v().getAppContext();

    public abstract void analyze();

    public void start() {
        OutputUtil.debug(String.format("[ ANALYZER ] Start to run analyzer %s", this.getClass().getSimpleName()));
        long startInMs = System.currentTimeMillis();
        try {
            analyze();
        } catch (Exception e) {
            OutputUtil.error(String.format("[ ANALYZER ] %s failed", this.getClass().getSimpleName()), e);
            throw new RuntimeException(String.format("[ ANALYZER ] %s failed", this.getClass().getSimpleName()), e);
        }
        ClientInfo.getInstance().setAnalyzerFinished(this.getClass().getSimpleName());
        ClientInfo.getInstance().setAnalyzerDuration(this.getClass().getSimpleName(), System.currentTimeMillis() - startInMs);
        OutputUtil.debug(String.format("[ ANALYZER ] %s took %.2f seconds", this.getClass().getSimpleName(), (System.currentTimeMillis() - startInMs) / 1000.0));
    }
}
