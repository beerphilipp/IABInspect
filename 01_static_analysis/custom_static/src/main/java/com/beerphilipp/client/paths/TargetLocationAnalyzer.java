package com.beerphilipp.client.paths;

import com.beerphilipp.CallChain;
import com.beerphilipp.Config;
import com.beerphilipp.StatementIdentity;
import com.beerphilipp.client.Analyzer;
import com.beerphilipp.util.Input;
import com.beerphilipp.util.OutputUtil;
import soot.PackManager;
import soot.Transform;

import java.util.ArrayList;
import java.util.List;

public class TargetLocationAnalyzer extends Analyzer {

    @Override
    public void analyze() {
        List<String> targetMethodSignatures = Input.readFileAsList(Config.targetMethodsPath);
        List<String> excludeLibraries = Input.readFileAsList(Config.excludedLibraries);

        if (targetMethodSignatures == null || excludeLibraries == null) {
            OutputUtil.error("Could not read target methods or excluded libraries file");
            throw new RuntimeException("Could not read target methods or excluded libraries file");
        }

        TargetLocationTransformer targetLocationTransformer = new TargetLocationTransformer(targetMethodSignatures);
        PackManager.v().getPack("jtp").add(new Transform("jtp.targetLocationTransformer", targetLocationTransformer));
        PackManager.v().runPacks();

        List<StatementIdentity> targetMethods = targetLocationTransformer.getTargetCallLocations(); // This list contains the target SootMethods from which the target methods are called
        OutputUtil.info("Found " + targetMethods.size() + " target methods");

        appContext.setTargetMethods(targetMethods);
    }
}
