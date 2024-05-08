package com.beerphilipp;

import java.nio.file.Paths;

public class Config {

    public static boolean singleMode = false;
    public static String singleModeApkPath =  null;
    public static String apkDirectory = null;
    public static String apkTxt = System.getProperty("user.dir") + "/apks.txt";
    public static String androidJarPath = System.getProperty("user.dir") + "/android-jars";
    public static String outputDir = System.getProperty("user.dir") + "/out/";
    public static String keyStore = System.getProperty("user.dir") + "/keystore/keystore.jks";
    public static String targetMethodsPath = System.getProperty("user.dir") + "/targetMethods.txt";
    public static Boolean deletePreviousOutput = true;
    public static String androidHome = System.getenv("ANDROID_HOME");
    public static String zipAlignLocation = Paths.get(androidHome, "build-tools/34.0.0/zipalign").toAbsolutePath().toString();
    public static String apkSignerLocation = Paths.get(androidHome, "build-tools/34.0.0/apksigner").toAbsolutePath().toString();
    public static boolean apkToolsOutput = true;
    public static String iccBotJar = System.getProperty("user.dir") + "/icc/ICCBot.jar";
    public static String iccOut = System.getProperty("user.dir") + "/iccOut/";
    public static int iccTimeout = 60;
    public static String iccBotConfig = System.getProperty("user.dir") + "/icc/config.json";
    public static String excludedLibraries = System.getProperty("user.dir") + "/exclude.txt";
    public static boolean shouldInstrument = true;
    public static boolean ignoreIcc = false;
    public static int pathTimeout = 60 * 5;
}
