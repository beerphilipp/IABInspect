package com.beerphilipp.icc;

import com.beerphilipp.App;
import com.beerphilipp.AppContext;
import com.beerphilipp.Config;
import com.beerphilipp.icc.iccbot.mappings.ComponentInfo_Component;
import com.beerphilipp.icc.iccbot.mappings.ComponentInfo_Receive;
import com.beerphilipp.icc.iccbot.mappings.ComponentInfo_Root;
import com.beerphilipp.models.components.ActivityModel;
import com.beerphilipp.models.components.ComponentModel;
import com.beerphilipp.models.components.IntentData;
import com.beerphilipp.util.Input;
import com.beerphilipp.util.OutputUtil;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class ICCExtraction {

    AppContext appContext;
    boolean alreadyRan;

    public ICCExtraction(AppContext appContext) {
        this.appContext = appContext;
        this.alreadyRan = false;
    }

    private boolean startICCBot(String apkFileName) {
        OutputUtil.info("Starting ICCBot");
        String apkFileNameWithEnding = apkFileName + ".apk";
        String[] command = new String[]{"java", "-Xmx50g", "-jar", Config.iccBotJar, "-path", Config.apkDirectory, "-name", apkFileNameWithEnding,
                "-time", String.valueOf(Config.iccTimeout), "-maxPathNumber", "100", "-client", "CTGClient", "-outputDir", Config.iccOut, "-androidJar", Config.androidJarPath, "-config", Config.iccBotConfig};

        // Execute this command
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            // print all the output from the process
            String line;
            java.io.BufferedReader input = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
            while ((line = input.readLine()) != null) {
                System.out.println(line);
            }
            input.close();

            long timeout = Config.iccTimeout + 7;
            boolean finished = p.waitFor(timeout, TimeUnit.MINUTES);
            if (!finished) {
                p.destroy();
                OutputUtil.error("ICCBot took too long to run");
                App.v().getAppContext().setIccTimeout(true);
                return false;
            }

            // get the error code from the process
            int exitVal = p.exitValue();
            if (exitVal != 0) {
                OutputUtil.error("Could not run ICCBot");
                return false;
            }

        } catch (Exception e) {
            OutputUtil.error("Could not run ICCBot", e);
            return false;
        }
        return true;
    }

    public List<ICCEdge> extractICC() {
        return extractICCWithIccBot();
    }

    public void extractIntentInformation() {
        String apkFileName = Paths.get(appContext.getAbsolutePath()).getFileName().toString();
        String apkName = apkFileName.split(".apk")[0];
        String iccBotComponentInfo = Paths.get(Config.iccOut, apkName, "CTGResult", "componentInfo.xml").toAbsolutePath().toString();
        if (!Input.fileExists(iccBotComponentInfo) && !alreadyRan) {
            alreadyRan = true;
            startICCBot(apkName);
        }
        if (!Input.fileExists(iccBotComponentInfo)) {
            OutputUtil.error("Could not determine ICC edges.");
            appContext.setIntentExtractionSuccess(false);
        } else {
            appContext.setIntentExtractionSuccess(true);
            ComponentInfo_Root componentInfoRoot = Input.readIccBotComponentInfo(iccBotComponentInfo);
            if (componentInfoRoot == null) {
                OutputUtil.error("Error extracting ICC information");
                return;
            }

            for (ComponentInfo_Component component : componentInfoRoot.getComponents()) {
                if (component.getType().equals("Activity")) {
                    ComponentInfo_Receive receive = component.getReceive();
                    if (receive == null) {
                        continue;
                    }
                    String data = receive.getData();
                    String rawExtras = receive.getExtras();
                    HashMap<String, String> extras = parseRawExtras(rawExtras);
                    IntentData intentData = new IntentData(data, extras);

                    // Find the activity in the app context and also set all alias activities
                    String activityName = component.getName();
                    for (ComponentModel componentModel : appContext.getActivityMap().values()) {
                        if (Objects.equals(componentModel.getComponentName(), activityName)) {
                            componentModel.setIntentData(intentData);
                        }
                        if (componentModel instanceof ActivityModel) {
                            ActivityModel activityModel = (ActivityModel) componentModel;
                            if (Objects.equals(activityModel.getAliasFor(), activityName)) {
                                activityModel.setIntentData(intentData);
                            }
                        }
                    }
                }
            }

        }
    }

    private HashMap<String, String> parseRawExtras(String rawExtras) {
        if (rawExtras == null) {
            return new HashMap<>();
        }
        HashMap<String, String> result = new HashMap<>();
        String[] extras = rawExtras.split(",");
        for (String extra: extras) {
            String cleanedExtra = extra.trim();
            if (!cleanedExtra.isEmpty()) {
                String[] keyValue = cleanedExtra.split("-");
                if (keyValue.length > 2) {
                    String type = keyValue[0];
                    String name = keyValue[1];
                    if (name.endsWith(")")) {
                        name = name.substring(0, name.length() - 1);
                    }
                    if (name.startsWith(".")) {
                        name = name.substring(1);
                    }
                    result.put(name, type);
                }
            }

        }
        return result;
    }


    public List<ICCEdge> extractICCWithIccBot() {

        String apkFileName = Paths.get(appContext.getAbsolutePath()).getFileName().toString();
        String apkName = apkFileName.split(".apk")[0];
        String iccBotCTG = Paths.get(Config.iccOut, apkName, "CTGResult", "CTG.xml").toAbsolutePath().toString();
        // if this file exists
        if (!Input.fileExists(iccBotCTG) && !alreadyRan) {
            alreadyRan = true;
            startICCBot(apkName);
        }

        if (!Input.fileExists(iccBotCTG)) {
            OutputUtil.error("Could not determine ICC edges.");
            appContext.setIccSuccess(false);
            return new ArrayList<>();
        } else {
            appContext.setIccSuccess(true);
            List<ICCEdge> iccEdges = Input.readIccBotCTG(iccBotCTG);
            return iccEdges;
        }
    }
}
