package com.beerphilipp.client.instrumentation;

import com.beerphilipp.Config;
import com.beerphilipp.client.Analyzer;
import com.beerphilipp.util.ApkUtil;
import com.beerphilipp.util.OutputUtil;
import soot.PackManager;

import java.nio.file.Paths;

/**
 * Writes the APK file of the instrumented app.
 */
public class ApkWriter extends Analyzer {

    @Override
    public void analyze() {
        OutputUtil.trace("Writing APK file of " + appContext.getPackageName());
        PackManager.v().writeOutput();

        OutputUtil.trace("Aligning and signing APK file of " + appContext.getPackageName());
        String mergedApkFileName = Paths.get(appContext.getAbsolutePath()).getFileName().toString();

        String instrumentedAPKPath = Paths.get(Config.outputDir, appContext.getPackageName(), "instrumented", mergedApkFileName).toAbsolutePath().toString();
        boolean alignedAndSigned = ApkUtil.alignAndSign(
                OutputUtil.getInstrumentedSignedApkPath(appContext.getPackageName()),
                instrumentedAPKPath,
                Config.keyStore);

        if (!alignedAndSigned) {
            OutputUtil.error("APK not aligned and signed");
            throw new RuntimeException("APK of " + appContext.getPackageName() + " could not be aligned and signed");
        }

        OutputUtil.trace("Aligned and signed APK file of " + appContext.getPackageName());
        appContext.setInstrumentedApkPath(OutputUtil.getInstrumentedSignedApkPath(appContext.getPackageName()));

    }
}
