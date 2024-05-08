package com.beerphilipp.util;

import com.beerphilipp.PreliminaryStatementIdentity;
import com.beerphilipp.StatementIdentity;
import com.beerphilipp.icc.ICCEdge;
import com.beerphilipp.icc.iccbot.mappings.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.google.gson.Gson;

import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.List;

/**
 * Utility class for reading input files.
 */
public class Input {

    /**
     * Read the given file, every line is an entry in the list.
     * Ignore lines starting with "#".
     *
     * @param filePath Path to the file
     * @return List of lines. Null if the file could not be read.
     */
    public static List<String> readFileAsList(String filePath) {
        // Read the given file, every line is an entry in the list
        List<String> lines = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("#") || line.isEmpty()) {
                    continue;
                }
                lines.add(line);
            }
        } catch (IOException e) {
            OutputUtil.error("Could not read file: " + filePath);
            return null;
        }
        return lines;
    }

    /**
     * Reads the input apk files from the given file.
     * The file should be a json file with the following format:
     * {
     *    "package.name": {
     *        "mode": "SINGLE_APK | MULTIPLE_APKs",
     *        "split_apks": [
     *          "base.apk",
     *          "config.en.apk"
     *        ]
     *    }
     *  }
     *  If the mode is SINGLE_APK, the split_apks field is ignored.
     *  If the mode is MULTIPLE_APKs, the split_apks field is used to specify the split apks.
     *
     * @param filePath Path to the file
     * @return Map of package name to apk files. Null if the file could not be read.
     */
    public static Map<String, String[]> readInputApkFile(String filePath) {
        // read a file as json
        File jsonFile = new File(filePath);
        HashMap<String, String[]> apps = new HashMap<>();

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(jsonFile);

            jsonNode.fieldNames().forEachRemaining(fieldName -> {
                JsonNode value = jsonNode.get(fieldName);
                String[] allApkFiles;
                if (value.get("split_apks") != null) {
                    String[] splitApks = new Gson().fromJson(value.get("split_apks").toString(), String[].class);
                    allApkFiles = new String[splitApks.length + 1];
                    allApkFiles[0] = fieldName + ".apk";
                    System.arraycopy(splitApks, 0, allApkFiles, 1, splitApks.length);
                } else {
                    allApkFiles = new String[]{fieldName + ".apk"};
                }
                apps.put(fieldName, allApkFiles);
            });
            return apps;
        } catch (IOException e) {
            OutputUtil.error("A problem occurred when reading the input file", e);
            return null;
        }
    }

    public static Map<PreliminaryStatementIdentity, List<String>> readVSAResult(String filePath) {
        File jsonFile = new File(filePath);
        HashMap<PreliminaryStatementIdentity, List<String>> results = new HashMap<>();

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(jsonFile);
            JsonNode valuePointsNode = jsonNode.get("ValuePoints");
            // iterate over the valuePointsNode array
            for (JsonNode valuePoint : valuePointsNode) {
                String sootMethodString = valuePoint.get("SootMethod").asText();
                int startLineNumber = new Gson().fromJson(valuePoint.get("startLineNumber").toString(), Integer.class);
                String unitString = valuePoint.get("Unit").asText();
                PreliminaryStatementIdentity statementIdentity = new PreliminaryStatementIdentity(sootMethodString, unitString, startLineNumber);

                JsonNode valueSetNode = valuePoint.get("ValueSet");
                List<String> values = new ArrayList<>();
                for (JsonNode valueSetEntry : valueSetNode) {
                    valueSetEntry.fieldNames().forEachRemaining(parameterIndex -> {
                        JsonNode arrayNode = valueSetEntry.get(parameterIndex);
                        for (JsonNode value : arrayNode) {
                            values.add(value.asText());
                        }
                    });
                }
                results.put(statementIdentity, values);
            }
            return results;
        } catch (IOException e) {
            OutputUtil.error("A problem occurred when reading the input file", e);
            return null;
        }
    }

    public static List<ICCEdge> readIccBotResult(String filePath) {
        File xmlFile = new File(filePath);
        XmlMapper xmlMapper = new XmlMapper();
        ICCBotRoot iccBotRoot = null;
        try {
            iccBotRoot = xmlMapper.readValue(xmlFile, ICCBotRoot.class);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        if (iccBotRoot == null) {
            return new ArrayList<>();
        }

        List<ICCBotRoot.ICCBotComponent> components = iccBotRoot.getComponents();
        if (components == null) {
            return new ArrayList<>();
        }



        return new ArrayList<>();

    }

    public static ComponentInfo_Root readIccBotComponentInfo(String filePath) {
        File xmlFile = new File(filePath);
        XmlMapper xmlMapper = new XmlMapper();
        ComponentInfo_Root componentInfoRoot = null;
        try {
            componentInfoRoot = xmlMapper.readValue(xmlFile, ComponentInfo_Root.class);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return componentInfoRoot;

    }

    public static List<ICCEdge> readIccBotCTG(String filePath) {
        File xmlFile = new File(filePath);
        XmlMapper xmlMapper = new XmlMapper();
        CTG_Root ctg = null;
        try {
            ctg = xmlMapper.readValue(xmlFile, CTG_Root.class);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        if (ctg == null) {
            return new ArrayList<>();
        }

        // Map those to ICCEdges
        List<ICCEdge> iccEdges = new ArrayList<>();
        if (ctg.getSources() == null) {
            return iccEdges;
        }
        for (CTG_Source source : ctg.getSources()) {
            // TODO This covers only Activity -> X ICCs
            if (source.getDestinations() == null || !"Activity".equals(source.getType())) {
                continue;
            }
            for (CTG_Destination destination : source.getDestinations()) {

                // TODO this covers only EXPLICIT icc where the destination is an Activity
                if ("Activity".equals(destination.getDesType()) && "explicit".equals(destination.getIccType()) && "Act2Act".equals(destination.getEdgeType())) {
                    ICCEdge iccEdge = new ICCEdge();
                    iccEdge.setSourceActivity(source.getName());
                    iccEdge.setTargetActivity(destination.getName());
                    String extras = destination.getExtras();
                    // since we only cover explicit activity -> activity intents for now, the destination method is always the onCreate method

                    StatementIdentity sourceStatement = StatementIdentity.getStatementIdentityByInstructionId(destination.getMethod(), destination.getUnit(), destination.getInstructionId());
                    if (sourceStatement == null) {
                        continue;
                    }
                    iccEdge.setSource(sourceStatement);
                    if (extras != null && !extras.isEmpty()) {
                        String[] splitExtras = extras.split(",");
                        iccEdge.setExtras(List.of(splitExtras));
                    }

                    iccEdges.add(iccEdge);


                }

            }
        }
        return iccEdges;

    }

    public static boolean fileExists(String filePath) {
        File file = new File(filePath);
        return file.exists();
    }

}
