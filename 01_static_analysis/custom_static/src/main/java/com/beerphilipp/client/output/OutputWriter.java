package com.beerphilipp.client.output;

import com.beerphilipp.ClientInfo;
import com.beerphilipp.Config;
import com.beerphilipp.actions.*;
import com.beerphilipp.client.Analyzer;
import com.beerphilipp.models.components.ActivityModel;
import com.beerphilipp.models.components.IntentData;
import com.beerphilipp.models.components.IntentFilterData;
import com.beerphilipp.models.components.IntentFilterModel;
import com.beerphilipp.util.OutputUtil;
import org.modelmapper.ModelMapper;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OutputWriter extends Analyzer {

    private ActionResult result;

    @Override
    public void analyze() {
        this.result = new ActionResult();

        result.setPackageName(appContext.getPackageName());

        // if hybrid app analyzer finished
        result.setHybridApp(appContext.getIsHybridApp());

        // if manifest analyzer finished
        result.setOriginalApkPath(appContext.getAbsolutePath());

        // if paths analyzer finished
        result.setActionTargets(appContext.getActionTargets());

        // if instrumentation analyzer finished
        result.setInstrumentedApkPath(appContext.getInstrumentedApkPath());

        result.setIccSuccess(appContext.isIccSuccess());

        result.setIntentExtrasSuccess(appContext.isIntentExtractionSuccess());

        result.setIccTimeout(appContext.isIccTimeout());

        if (appContext.getExceptionOccurred() != null) {
            Exception e = appContext.getExceptionOccurred();
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            String exceptionString = sw.toString();
            result.setException(exceptionString);
        }

        setDurations();

        setActivities();


        String outputFilePath = Paths.get(Config.outputDir, appContext.getPackageName(), "res.json").toAbsolutePath().toString();
        OutputUtil.writeJsonToFile(outputFilePath, result);

    }

    private void setDurations() {
        Map<String, Long> clientDurations = ClientInfo.getInstance().getClientDurationMap();
        Map<String, Long> analyzerDurations = ClientInfo.getInstance().getAnalyzerDurationMap();

        long hybridAppClientDuration = clientDurations.getOrDefault("HybridAppClient", 0L);
        long manifestClientDuration = clientDurations.getOrDefault("ManifestClient", 0L);
        long callGraphClientDuration = clientDurations.getOrDefault("CallGraphClient", 0L);
        long iccClientDuration = clientDurations.getOrDefault("ICCClient", 0L);
        long pathFinderClientDuration = clientDurations.getOrDefault("PathFinderClient", 0L);
        long instrumentationClient = clientDurations.getOrDefault("InstrumentationClient", 0L);

        result.setHybridAppClientDuration(hybridAppClientDuration / 1000);
        result.setManifestClientDuration(manifestClientDuration / 1000);
        result.setCallGraphClientDuration(callGraphClientDuration / 1000);
        result.setIccClientDuration(iccClientDuration / 1000);
        result.setPathFinderClientDuration(pathFinderClientDuration / 1000);
        result.setInstrumentationClientDuration(instrumentationClient / 1000);

        long duration = 0L;
        for (String clientName : clientDurations.keySet()) {
            Long currDuration = ClientInfo.getInstance().getClientDurationMap().get(clientName);
            if (currDuration == null) {
                currDuration = 0L;
            }
            duration += currDuration;
        }
        result.setTotalDuration(duration / 1000);
    }

    private void setActivities() {
        ArrayList<ActivityOut> activities = new ArrayList<>();
        for (String activityName : appContext.getActivityMap().keySet()) {
            ActivityModel activityModel = (ActivityModel) appContext.getActivityMap().get(activityName);
            ActivityOut activityOut = new ActivityOut();
            activityOut.setName(activityModel.getComponentName());
            activityOut.setAliasFor(activityModel.getAliasFor());
            activityOut.setExported(activityModel.isExported());

            IntentDataOut intentDataOut = new IntentDataOut();
            if (activityModel.getIntentData() != null) {
                intentDataOut.setData(activityModel.getIntentData().getData());
                if (activityModel.getIntentData().getExtras() != null) {
                    for (Map.Entry<String, String> entry : activityModel.getIntentData().getExtras().entrySet()) {
                        IntentExtraOut intentExtraOut = new IntentExtraOut();
                        intentExtraOut.setName(entry.getKey());
                        intentExtraOut.setType(entry.getValue());
                        intentDataOut.getExtras().add(intentExtraOut);
                    }
                }
            }

            activityOut.setIntent(intentDataOut);

            List<IntentFilterOut> intentFilterOuts = new ArrayList<>();

            for (IntentFilterModel intentFilterModel : activityModel.getIntentFilterList()) {
                IntentFilterOut intentFilterOut = new IntentFilterOut();
                intentFilterOut.setActions(new ArrayList<>(intentFilterModel.getActionList()));
                intentFilterOut.setCategories(new ArrayList<>(intentFilterModel.getCategoryList()));

                List<IntentFilterDataOut> intentFilterDataOuts = new ArrayList<>();
                if (intentFilterModel.getDataList() != null) {
                    for (IntentFilterData intentFilterData : intentFilterModel.getDataList()) {
                        ModelMapper modelMapper = new ModelMapper();
                        IntentFilterDataOut intentFilterDataOut = modelMapper.map(intentFilterData, IntentFilterDataOut.class);
                        intentFilterDataOuts.add(intentFilterDataOut);
                    }
                }
                intentFilterOut.setData(intentFilterDataOuts);
                intentFilterOuts.add(intentFilterOut);
            }
            activityOut.setIntentFilters(intentFilterOuts);
            activities.add(activityOut);
        }
        result.setActivities(activities);
    }
}
