package com.beerphilipp.client.instrumentation;

import soot.Body;

/**
 * Represents an Instrumentor. An implemenation of this interface is used to instrument a body of a method.
 *
 */
public interface Instrumentor {

    /**
     * Instruments the body of a method.
     * @param body The body of the method
     */
    void instrument(Body body);
}
