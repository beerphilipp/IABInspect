package com.beerphilipp.client.callgraph;

import com.beerphilipp.Config;
import com.beerphilipp.client.Analyzer;
import com.beerphilipp.util.SetupUtil;
import soot.Scene;
import soot.SootClass;
import soot.jimple.infoflow.android.callbacks.AndroidCallbackDefinition;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.util.MultiMap;

public class CallGraphConstructor extends Analyzer {

    @Override
    public void analyze() {
        MySetupApplication app = SetupUtil.setupFlowDroid(appContext.getPackageName(), appContext.getAbsolutePath(), Config.androidJarPath);
        app.constructCallgraph();
        CallGraph callGraph = Scene.v().getCallGraph();
        appContext.setCallGraph(callGraph);
        appContext.setDummyMainMethod(app.getDummyMainMethod());

        MultiMap<SootClass, AndroidCallbackDefinition> callbackMethods = app.getCallbackMethods();
        appContext.setCallbackMethods(callbackMethods);
    }
}
