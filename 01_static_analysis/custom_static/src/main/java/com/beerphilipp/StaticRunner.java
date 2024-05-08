package com.beerphilipp;

import com.beerphilipp.client.callgraph.CallGraphClient;
import com.beerphilipp.client.hybridApp.HybridAppClient;
import com.beerphilipp.client.icc.ICCClient;
import com.beerphilipp.client.instrumentation.InstrumentationClient;
import com.beerphilipp.client.manifest.ManifestClient;
import com.beerphilipp.client.output.OutputClient;
import com.beerphilipp.client.paths.PathFinderClient;
import com.beerphilipp.util.FileUtil;
import com.beerphilipp.util.OutputUtil;


/**
 * This class is used as an entry point to run the static analysis.
 */
public class StaticRunner {

    /*private void setupICCBot(APKContext apkContext) {
        MyConfig myConfig = MyConfig.getInstance();

        myConfig.setJimple(true);
        myConfig.setAppPath(Config.apkLocation + "/");
        String apkFileName = Paths.get(apkContext.getAbsolutePath()).getFileName().toString();
        myConfig.setAppName(apkFileName);

        myConfig.setAndroidJar(Config.androidJarPath);
        myConfig.setWriteSootOutput(true);

        int timeLimit = 90;
        myConfig.setTimeLimit(timeLimit);
        myConfig.setMaxPathNumber(100);
        myConfig.setMaxFunctionExpandNumber(10);
        myConfig.setMaxObjectSummarySize(1000);
        myConfig.setCallGraphAlgorithm("SPARK");

        //if (!mCmd.hasOption("name")) {
        //    printHelp("Please input the apk name use -name.");
        //}

        // Load Analyze Config
        Path fPath = Paths.get(Config.iccBotConfig);
        if (!Files.exists(fPath)) {
            OutputUtil.error("Failed to load analyze config json: File not exist");
            System.exit(0);
        }

        JSONObject analyzeConfig = null;
        try {
            analyzeConfig = JSON.parseObject(String.join("\n", Files.readAllLines(fPath)));
            myConfig.setAnalyzeConfig(analyzeConfig);
        } catch (IOException e) {
            OutputUtil.error("Failed to load analyze config json: IOException", e);
            System.exit(0);
        }
        // Initialize SootUtils.excludePackages

        JSONArray excArr = MyConfig.getInstance().getAnalyzeConfig().getJSONArray("SootAnalyzer.excludePackages");
        if (excArr == null) return;
        List<String> excList = excArr.toJavaList(String.class);
        List<String> excPkgList = new ArrayList<>();
        for (String expr : excList) {
            excPkgList.add("<" + expr.replaceAll("\\*", ""));
        }
        SootUtils.setExcludePackages(excPkgList);
    }

    private void getICCs(APKContext apkContext) {
        setupICCBot(apkContext);
        BaseClient cgClient = new CallGraphClient();
        cgClient.start();
        CallGraph callGraph = Scene.v().getCallGraph();
        System.out.println(callGraph);
    }*/

    public void run(String filePath) {
        App.reset();

        App.v().setApkPath(filePath);

        try {
            // Check if this app is a hybrid app
            HybridAppClient hybridAppClient = new HybridAppClient();
            hybridAppClient.start();

            // Analyze the Manifest file to get, among others, the exported activities
            ManifestClient manifestClient = new ManifestClient();
            manifestClient.start();

            // We remove the previous output directory, but keep the callback and callgraph files
            if (Config.deletePreviousOutput) {
                OutputUtil.deletePreviousOutput();
            }

            // Create the call graph
            CallGraphClient callGraphClient = new CallGraphClient();
            callGraphClient.start();

            if (! Config.ignoreIcc) {
                ICCClient iccClient = new ICCClient();
                iccClient.start();
            }

            // Find the paths to the target methods
            PathFinderClient pathFinderClient = new PathFinderClient();
            pathFinderClient.start();

            if (Config.shouldInstrument) {
                // instrument the application
                InstrumentationClient instrumentationClient = new InstrumentationClient();
                instrumentationClient.start();
            }

        } catch (Exception e) {
            e.printStackTrace();
            App.v().getAppContext().setExceptionOccurred(e);
        }

        // Output the results
        OutputClient outputClient = new OutputClient();
        outputClient.start();

    }

}
