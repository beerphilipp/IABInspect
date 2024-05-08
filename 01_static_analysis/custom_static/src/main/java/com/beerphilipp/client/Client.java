package com.beerphilipp.client;

import com.beerphilipp.ClientInfo;
import com.beerphilipp.util.OutputUtil;

/**
 * Base class for all clients.
 *
 * A client is a class that performs a specific analysis on a given app.
 * Subclasses of this class should implement only the analyze method.
 *
 * One client may call multiple analyzers to perform its task.
 *
 */
public abstract class Client {

    public void start() {
        OutputUtil.info(String.format("[ CLIENT ] Start to run client %s", this.getClass().getSimpleName()));
        long startInMs = System.currentTimeMillis();
        try {
            analyze();
        } catch (Exception e) {
            OutputUtil.error(String.format("[ CLIENT ] %s failed", this.getClass().getSimpleName()), e);
            throw new RuntimeException(String.format("[ CLIENT ] %s failed", this.getClass().getSimpleName()), e);
        }
        ClientInfo.getInstance().setClientFinished(this.getClass().getSimpleName());
        ClientInfo.getInstance().setClientDuration(this.getClass().getSimpleName(), System.currentTimeMillis() - startInMs);
        OutputUtil.info(String.format("[ CLIENT ] %s took %.2f seconds", this.getClass().getSimpleName(), (System.currentTimeMillis() - startInMs) / 1000.0));

    }
    protected abstract void analyze();
}
