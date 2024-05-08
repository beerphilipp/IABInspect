package com.beerphilipp.client.callgraph;

import com.beerphilipp.*;
import com.beerphilipp.client.Client;
import com.beerphilipp.client.hybridApp.HybridAppClient;
import com.beerphilipp.client.icc.ICCAnalyzer;
import com.beerphilipp.client.manifest.ManifestClient;
import com.beerphilipp.client.paths.TargetLocationAnalyzer;
import com.beerphilipp.util.Input;
import com.beerphilipp.util.OutputUtil;
import soot.jimple.toolkits.callgraph.CallGraph;

import java.nio.file.Paths;
import java.util.List;

public class CallGraphClient extends Client {

    @Override
    protected void analyze() {

        if (!ClientInfo.getInstance().isFinished(HybridAppClient.class)) {
            HybridAppClient hybridAppClient = new HybridAppClient();
            hybridAppClient.start();
        }

        Boolean isHybridApp = App.v().getAppContext().getIsHybridApp();
        if (isHybridApp) {
            return;
        }

        if (!ClientInfo.getInstance().isFinished(ManifestClient.class)) {
            ManifestClient manifestClient = new ManifestClient();
            manifestClient.start();
        }

        // If the app only contains calls to the target methods inside methods that we exclude, we can early exit here.
        CallGraphConstructor callGraphConstructor = new CallGraphConstructor();
        callGraphConstructor.start();

        saveCallGraph();

        // We do an early exit here in case all of the targeted methods are excluded

        TargetLocationAnalyzer targetLocationAnalyzer = new TargetLocationAnalyzer();
        targetLocationAnalyzer.start();

        if (onlyExcludedMethods()) {
            App.v().getAppContext().setOnlyContainsExcludedMethods(true);
            OutputUtil.info("Only excluded methods found in call graph. Skipping instrumentation.");
            return;
        }

        CallGraphModifier callGraphModifier = new CallGraphModifier();
        callGraphModifier.start();
    }


    private boolean onlyExcludedMethods() {
        List<String> excludeLibraries = Input.readFileAsList(Config.excludedLibraries);
        if (excludeLibraries == null) {
            throw new RuntimeException("Could not read excluded libraries file");
        }

        for (StatementIdentity node : App.v().getAppContext().getTargetMethods()) {
            if (excludeLibraries.stream().noneMatch(excludedLibrary -> node.getMethod().getSignature().startsWith("<" + excludedLibrary))) {
                return false;
            }
        }
        return true;
    }


    private void saveCallGraph() {
        CallGraph callGraph = App.v().getAppContext().getCallGraph();
        String cg = callGraph.toString();
        OutputUtil.writeToFile(Paths.get(Config.outputDir, App.v().getAppContext().getPackageName(), "callgraph.txt").toString(), cg);
    }
}
