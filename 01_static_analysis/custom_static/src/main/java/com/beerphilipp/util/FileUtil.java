package com.beerphilipp.util;

import java.io.File;

public class FileUtil {

    /**
     * Create a directory if it does not exist
     * @param path The path to the directory
     * @return true if the directory was created, false otherwise
     */
    public static boolean createDirectoryIfNotExists(String path) {
        File file = new File(path);
        if (!file.exists()) {
            return file.mkdir();
        }
        return false;
    }

    public static boolean copyFile(String source, String destination) {
        File sourceFile = new File(source);
        File destinationFile = new File(destination);
        if (sourceFile.exists()) {
            try {
                org.apache.commons.io.FileUtils.copyFile(sourceFile, destinationFile);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return false;
    }
}
