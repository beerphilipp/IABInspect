package com.beerphilipp.client.instrumentation;

import soot.Body;
import soot.BodyTransformer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class InstrumentationTransformer extends BodyTransformer {
    
    private final List<Instrumentor> instrumentors = new ArrayList<>();

    public void addInstrumentor(Instrumentor instrumentor) {
        this.instrumentors.add(instrumentor);
    }

    @Override
    protected void internalTransform(Body body, String s, Map<String, String> map) {
        for (Instrumentor instrumentor: instrumentors) {
            instrumentor.instrument(body);
        }
    }
}
