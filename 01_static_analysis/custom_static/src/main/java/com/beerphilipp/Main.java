package com.beerphilipp;

import com.beerphilipp.util.OutputUtil;
import com.beerphilipp.util.Input;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;


import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;


public class Main {

    private static final Logger logger = LogManager.getLogger(Main.class);

    public static void main(String[] args) {

        CommandLine cmd = getCommandLine(args);
        if (cmd == null) {
            return;
        }

        analyzeCommandLineOptions(cmd);

        OutputUtil.setOutputEnabled(true);
        StaticRunner staticRunner = new StaticRunner();

        List<String> fileNames = new ArrayList<>();
        if (Config.singleMode) {
            // Single APK Mode
            fileNames.add(Config.singleModeApkPath);
        } else {
            // Multi APK Mode
            List<String> relativeFileNames = Input.readFileAsList(Config.apkTxt);
            if (relativeFileNames == null) {
                OutputUtil.error("Could not read APK files from directory: " + Config.apkTxt);
                return;
            }
            for (String relativeFileName : relativeFileNames) {
                fileNames.add(Paths.get(Config.apkDirectory, relativeFileName).toAbsolutePath().toString());
            }
        }

        for (String fileName : fileNames) {
            logger.info("Analyzing app: " + fileName);
            try {
                staticRunner.run(fileName);
            } catch (Exception e) {
                logger.error("Error while analyzing app: " + fileName);
                throw new RuntimeException("Error while analyzing app: " + fileName, e);
            }
        }

        System.exit(0);
        // TODO add timeout for analysis, see https://github.com/secure-software-engineering/FlowDroid/issues/578 for suggested values
    }

    private static CommandLine getCommandLine(String[] args) {
        CommandLineParser parser = new DefaultParser();
        try {
            return parser.parse(getCommandLineOptions(), args);
        } catch (Exception e) {
            OutputUtil.error("Error while parsing command line arguments: " + e.getMessage());
            return null;
        }
    }

    private static Options getCommandLineOptions() {
        Options options = new Options();
        options.addOption("apkDir", true, "Directory containing the APKs to analyze. Only necessary when multiple APKs should be analyzed.");
        options.addOption("apkTxt", true, "File containing the file names to analyze. Only necessary when multiple APKs should be analyzed.");
        options.addOption("apk", true, "Single APK to analyze");
        options.addOption("androidHome", true, "Path to the Android SDK. Default: $ANDROID_HOME");
        options.addOption("noInstrumentation", false, "Skips the instrumentation step");
        options.addOption("deletePreviousOutputKeepCB", false, "Deletes the previous output directory and keeps the callgraph and the callbacks");
        options.addOption("iccTimeout", true, "Timeout for ICCBot (in minutes)");
        options.addOption("ignoreIcc", false, "Ignore ICC analysis");
        return options;
    }

    private static void analyzeCommandLineOptions(CommandLine commandLine) {
        if ((commandLine.hasOption("apkDir") || commandLine.hasOption("apkTxt")) && commandLine.hasOption("apk")) {
            OutputUtil.error("You can only specify either (apkDir and apkTxt) or (apk)");
            System.exit(1);
        }

        if (commandLine.hasOption("apkDir")) {
            Config.apkDirectory = commandLine.getOptionValue("apkDir");
        }

        if (commandLine.hasOption("apkTxt")) {
            Config.apkTxt = commandLine.getOptionValue("apkTxt");
        }

        if (commandLine.hasOption("apk")) {
            Config.singleMode = true;
            Config.singleModeApkPath = commandLine.getOptionValue("apk");
            Config.apkDirectory = Paths.get(Config.singleModeApkPath).getParent().toString();
        }

        if (commandLine.hasOption("androidHome")) {
            Config.androidHome = commandLine.getOptionValue("androidHome");
        }

        if (commandLine.hasOption("noInstrumentation")) {
            Config.shouldInstrument = false;
        }
        if (commandLine.hasOption("deletePreviousOutputKeepCB")) {
            Config.deletePreviousOutput = true;
        }

        if (commandLine.hasOption("iccTimeout")) {
            Config.iccTimeout = Integer.parseInt(commandLine.getOptionValue("iccTimeout"));
        }

        if (commandLine.hasOption("ignoreIcc")) {
            Config.ignoreIcc = true;
        }
    }




}