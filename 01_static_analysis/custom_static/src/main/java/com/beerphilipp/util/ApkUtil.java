package com.beerphilipp.util;

import com.beerphilipp.Config;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.ZipFile;

/**
 * This class contains utility functions for APK handling.
 */
public class ApkUtil {

    /**
     * Checks if the given apk file is a hybrid app.
     * @param inputFile The apk file
     * @return true if the apk file is a hybrid app, false otherwise
     */
    public static boolean isHybridApp(String inputFile) {
        if (isCordovaApp(inputFile)) {
            return true;
        }
        // TODO figure out if/how we can detect other hybrid apps
        return false;
    }

    private static boolean isCordovaApp(String inputFile) {
        String cordovaDirectory = "assets/www/cordova.js";
        try (ZipFile zipFile = new ZipFile(inputFile)) {
            return zipFile.getEntry(cordovaDirectory) != null;
        } catch (IOException e) {
            OutputUtil.error("Could not check if the app is a Cordova app", e);
            return false;
        }
    }


    /**
     * Aligns and signs the APK.
     * The aligned and signed APK is saved in the output directory as apk_name-instrumented.apk.
     *
     * @param outputFile the absolute path to the output file
     * @param inputFile the absolute path to the input file
     * @param keyStore the absolute path to the keystore
     *
     * @return true if successful, false otherwise
     */
    public static boolean alignAndSign(String outputFile, String inputFile, String keyStore) {
        String zipAlignCommand = Config.zipAlignLocation + " -p -f -v 4 " +
                inputFile + " " +
                outputFile;

        ProcessBuilder processBuilder = new ProcessBuilder(zipAlignCommand.split("\\s+"));
        processBuilder.redirectErrorStream(true);
        try {
            Process process = processBuilder.start();
            // if Config.apkToolsOutput is true, we print the output of the apktool command
            if (Config.apkToolsOutput) {
                InputStream inputStream = process.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

                String line;
                while ((line = reader.readLine()) != null) {
                    //System.out.println(line);
                }
            }
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                return false;
            }
        } catch (IOException | InterruptedException e) {
            OutputUtil.error("Error while executing command: " + zipAlignCommand);
            OutputUtil.error(e.getMessage());
            return false;
        }
        OutputUtil.debug("Successfully aligned APK");

        // To create a keystore.jks, see: https://developer.android.com/studio/publish/app-signing#generate-key

        String signCommand = Config.apkSignerLocation + " sign --ks " + keyStore + " --ks-pass " + "pass:password " + outputFile;

        ProcessBuilder signProcessBuilder = new ProcessBuilder(signCommand.split("\\s+"));
        signProcessBuilder.redirectErrorStream(true);
        try {
            Process process = signProcessBuilder.start();
            if (Config.apkToolsOutput) {
                InputStream inputStream = process.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

                String line;
                while ((line = reader.readLine()) != null) {
                    //System.out.println(line);
                }
            }
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                return false;
            }
        } catch (IOException | InterruptedException e) {
            OutputUtil.error("Error while executing command: " + signCommand);
            OutputUtil.error(e.getMessage());
            return false;
        }

        return true;
    }
}
