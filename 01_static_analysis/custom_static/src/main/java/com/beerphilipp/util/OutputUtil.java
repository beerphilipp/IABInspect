package com.beerphilipp.util;

import com.beerphilipp.App;
import com.beerphilipp.Config;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;

public class OutputUtil {

    private static boolean enabled = true;
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_BLACK = "\u001B[30m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_PURPLE = "\u001B[35m";
    private static final String ANSI_CYAN = "\u001B[36m";
    private static final String ANSI_WHITE = "\u001B[37m";

    public static void setOutputEnabled(boolean enabled) {
        OutputUtil.enabled = enabled;
    }

    public static void trace(Object message) {
        if (OutputUtil.enabled) {
            String className = new Exception().getStackTrace()[1].getClassName();
            System.out.println(ANSI_BLUE + " " + "[ " + App.v().getAppContext().getPackageName() + " ] " + "[ TRACE ] " + "<" + className + ">:\t" + message + ANSI_RESET);
        }
    }

    public static void debug(Object message) {
        if (OutputUtil.enabled) {
            String className = new Exception().getStackTrace()[1].getClassName();
            System.out.println(ANSI_YELLOW + " " + "[ " + App.v().getAppContext().getPackageName() + " ] " + "[ DEBUG ] " + "<" + className + ">:\t" + message + ANSI_RESET);
        }
    }

    public static void info(Object message) {
        if (OutputUtil.enabled) {
            String className = new Exception().getStackTrace()[1].getClassName();
            System.out.println(ANSI_GREEN + " " + "[ " + App.v().getAppContext().getPackageName() + " ] " + "[ INFO ] " + "<" + className + ">:\t" + message + ANSI_RESET);
        }
    }

    public static void alert(Object message) {
        if (OutputUtil.enabled) {
            String className = new Exception().getStackTrace()[1].getClassName();
            System.out.println(ANSI_CYAN + " " + "[ " + App.v().getAppContext().getPackageName() + " ] " + "[ ALERT ] " + "<" + className + ">:\t" + message + ANSI_RESET);
        }
    }

    public static void special(Object message) {
        if (OutputUtil.enabled) {
            String className = new Exception().getStackTrace()[1].getClassName();
            System.out.println(ANSI_PURPLE + " " + "[ " + App.v().getAppContext().getPackageName() + " ] " + "[ SPECIAL ] " + "<" + className + ">:\t" + message + ANSI_RESET);
        }
    }

    public static void error(Object message) {
        if (OutputUtil.enabled) {
            String className = new Exception().getStackTrace()[1].getClassName();
            System.out.println(ANSI_RED + " " + "[ " + App.v().getAppContext().getPackageName() + " ] " + "[ ERROR ] " + "<" + className + ">:\t" + message + ANSI_RESET);
        }
    }

    public static void error(Object message, Object error) {
        if (OutputUtil.enabled) {
            String className = new Exception().getStackTrace()[1].getClassName();
            System.out.println(ANSI_RED + " " + "[ " + App.v().getAppContext().getPackageName() + " ] " + "[ ERROR ] " + "<" + className + ">:\t" + message + ANSI_RESET);
            System.out.println(ANSI_RED + " " + "[ " + App.v().getAppContext().getPackageName() + " ] " + "[ ERROR ] " + "<" + className + ">:\t" + error + ANSI_RESET);
        }
    }

    public static String getInstrumentedApkPath(String packageName) {
        return Paths.get(Config.outputDir, packageName, "instrumented", packageName + ".apk").toAbsolutePath().toString();
    }

    /**
     * Returns the absolute path to the instrumented and signed apk.
     * @param packageName The package name of the app
     * @return The absolute path to the instrumented and signed apk
     */
    public static String getInstrumentedSignedApkPath(String packageName) {
        return Paths.get(Config.outputDir, packageName, packageName + "-instrumented-signed" + ".apk").toAbsolutePath().toString();
    }


    /**
     * Writes the given object as JSON to the given file.
     * @param filePath The absolute path to the file
     * @param object The object to write to the file
     * @return true if successful, false otherwise
     */
    public static boolean writeJsonToFile(String filePath, Object object) {
        // check if the output directory exists
        String parent = Paths.get(filePath).getParent().toAbsolutePath().toString();
        ObjectMapper mapper = new ObjectMapper();
        try {
            Files.createDirectories(Paths.get(parent));
            String jsonString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(object);
            return writeToFile(filePath, jsonString);
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Writes the given content to the given file.
     * @param filePath The absolute path to the file
     * @param content The content to write to the file
     * @return true if successful, false otherwise
     */
    public static boolean writeToFile(String filePath, String content) {
        String parent = Paths.get(filePath).getParent().toAbsolutePath().toString();
        try {
            Files.createDirectories(Paths.get(parent));
            PrintWriter writer = new PrintWriter(filePath, "UTF-8");
            writer.println(content);
            writer.close();
        } catch (IOException e) {
            OutputUtil.error("Could not write to file " + filePath);
            return false;
        }
        return true;
    }

    /**
     * Deletes the output directory if Config.deletePreviousOutput is true.
     * @return true if successful, false otherwise
     */
    public static boolean deletePreviousOutput() {
        String packageOutputDir = Paths.get(Config.outputDir, App.v().getAppContext().getPackageName()).toAbsolutePath().toString();
        File outputDir = Paths.get(packageOutputDir).toFile();
        if (!outputDir.exists()) {
            return true;
        }
        try {
            File instrumentedDir = Paths.get(packageOutputDir, "instrumented").toFile();
            if (instrumentedDir.exists()) {
                FileUtils.deleteDirectory(instrumentedDir);
            }
            File resFile = Paths.get(packageOutputDir, "res.json").toFile();
            if (resFile.exists()) {
                FileUtils.delete(resFile);
            }
            File instrumentedApk = Paths.get(packageOutputDir, App.v().getAppContext().getPackageName() + "-instrumented-signed.apk").toFile();
            if (instrumentedApk.exists()) {
                FileUtils.delete(instrumentedApk);
            }
            File instrumentedIdsig = Paths.get(packageOutputDir, App.v().getAppContext().getPackageName() + "-instrumented-signed.apk.idsig").toFile();
            if (instrumentedIdsig.exists()) {
                FileUtils.delete(instrumentedIdsig);
            }
        } catch (IOException e) {
            OutputUtil.error("Could not delete the output directory");
            OutputUtil.error(e.getMessage());
            return false;
        }
        return true;
    }
}
