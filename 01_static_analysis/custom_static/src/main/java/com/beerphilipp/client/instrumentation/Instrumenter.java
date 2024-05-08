package com.beerphilipp.client.instrumentation;

import com.beerphilipp.Config;
import com.beerphilipp.client.Analyzer;
import com.beerphilipp.client.instrumentation.branches.BranchConditionInstrumentor;
import com.beerphilipp.client.instrumentation.logging.LoggingInstrumentor;
import com.beerphilipp.util.Input;
import soot.PackManager;
import soot.Transform;

import java.util.List;

public class Instrumenter extends Analyzer {

    @Override
    public void analyze() {
        List<String> targetMethodSignatures = Input.readFileAsList(Config.targetMethodsPath);

        InstrumentationTransformer instrumentationTransformer  = new InstrumentationTransformer();
        //BranchConditionInstrumentor branchConditionInstrumentor = new BranchConditionInstrumentor(appContext.getBranchConditionSet());
        LoggingInstrumentor loggingInstrumentor = new LoggingInstrumentor(targetMethodSignatures);

        //instrumentationTransformer.addInstrumentor(branchConditionInstrumentor);
        instrumentationTransformer.addInstrumentor(loggingInstrumentor);
        PackManager.v().getPack("jtp").add(new Transform("jtp.instrumentation", instrumentationTransformer));
        PackManager.v().runPacks();

    }
}
