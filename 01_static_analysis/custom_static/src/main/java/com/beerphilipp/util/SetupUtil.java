package com.beerphilipp.util;

import com.beerphilipp.AppContext;
import com.beerphilipp.App;
import com.beerphilipp.Config;
import com.beerphilipp.client.callgraph.MySetupApplication;
import soot.G;
import soot.JastAddJ.Opt;
import soot.Scene;
import soot.SootClass;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.options.Options;

import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class SetupUtil {

    public static SetupApplication setupFlowDroidNew(AppContext appContext) {
        InfoflowAndroidConfiguration configuration = new InfoflowAndroidConfiguration();
        configuration.getAnalysisFileConfig().setTargetAPKFile(appContext.getAbsolutePath());
        configuration.getAnalysisFileConfig().setAndroidPlatformDir(Config.androidJarPath);
        configuration.setCallgraphAlgorithm(InfoflowAndroidConfiguration.CallgraphAlgorithm.SPARK);
        SetupApplication app = new SetupApplication(configuration);
        app.setSootConfig(((options, config) -> {
            options.set_output_dir(Paths.get(Config.outputDir, appContext.getPackageName(), "instrumented").toString());
            options.set_output_format(Options.output_format_dex);
            options.set_src_prec(Options.src_prec_apk);

            List<String> excludeList = new LinkedList<String>();
            excludeList.add("java.*");
            excludeList.add("sun.misc.*");
            excludeList.add("android.*");
            excludeList.add("com.android.*");
            excludeList.add("dalvik.system.*");
            excludeList.add("org.apache.*");
            excludeList.add("soot.*");
            excludeList.add("javax.servlet.*");
            excludeList.add("dalvik.*");
            excludeList.add("kotlin.*");
            excludeList.add("androidx.*");
            excludeList.add("kotlinx.*");
            options.set_exclude(excludeList);
            options.set_no_bodies_for_excluded(true);
            //options.set_allow_phantom_refs(false);
        }));
        return app;
    }

    public static SetupApplication setupFlowDroidNew1(AppContext appContext) {
        InfoflowAndroidConfiguration configuration = new InfoflowAndroidConfiguration();
        configuration.getAnalysisFileConfig().setTargetAPKFile(appContext.getAbsolutePath());
        configuration.getAnalysisFileConfig().setAndroidPlatformDir(Config.androidJarPath);
        configuration.setCallgraphAlgorithm(InfoflowAndroidConfiguration.CallgraphAlgorithm.SPARK);
        configuration.setMergeDexFiles(true);
        configuration.setEnableReflection(true);
        configuration.setIgnoreFlowsInSystemPackages(true);

        SetupApplication app = new SetupApplication(configuration);
        app.setSootConfig((options, config) -> {
            options.set_include_all(true);

            // Based on  soot.jimple.infoflow.android.config.SootConfigForAndroid
            // explicitly include packages for shorter runtime:
            List<String> excludeList = new LinkedList<String>();
            excludeList.add("java.*");
            excludeList.add("javax.*");

            excludeList.add("sun.*");

            // exclude classes of android.* will cause layout class cannot be
            // loaded for layout file based callback analysis.

            // 2020-07-26 (SA): added back the exclusion, because removing it breaks
            // calls to Android SDK stubs. We need a proper test case for the layout
            // file issue and then see how to deal with it.
            excludeList.add("android.*");
            excludeList.add("androidx.*");

            excludeList.add("org.apache.*");
            excludeList.add("org.eclipse.*");
            excludeList.add("soot.*");
            excludeList.add("dalvik.");
            excludeList.add("kotlin.");
            excludeList.add("androidx.");
            excludeList.add("kotlinx.");
            excludeList.add("java.");
            excludeList.add("sun.misc.");
            excludeList.add("android.");
            excludeList.add("com.android.");
            excludeList.add("dalvik.system.");
            excludeList.add("org.apache.");
            excludeList.add("soot.");
            excludeList.add("javax.servlet.");
            excludeList.add("dalvik.");
            excludeList.add("kotlin.");
            excludeList.add("androidx.");
            excludeList.add("kotlinx.");
            options.set_exclude(excludeList);
            Options.v().set_no_bodies_for_excluded(true);
            options.set_src_prec(Options.src_prec_apk);
            options.set_output_format(Options.output_format_dex);
            options.set_output_dir(Paths.get(Config.outputDir, appContext.getPackageName(), "instrumented").toString());
            options.set_prepend_classpath(true);
            options.set_process_multiple_dex(true);
            options.set_soot_classpath("./libs/rt.jar");
            options.set_whole_program(true);
            options.set_include_all(true);

        });
        Scene.v().addBasicClass("java.io.PrintStream", SootClass.SIGNATURES);
        Scene.v().addBasicClass("java.lang.System",SootClass.SIGNATURES);
        Scene.v().loadNecessaryClasses();
        return app;
    }

    public static void setupSootFast() {
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars(Config.androidJarPath);
        Options.v().set_process_dir(Collections.singletonList(App.v().getAppContext().getAbsolutePath())); // maybe need to comment this in if you use set_process_multiple_dex

        Options.v().set_process_multiple_dex(true);
        Options.v().set_prepend_classpath(true);
        Options.v().set_soot_classpath("./libs/rt.jar");

        Options.v().set_allow_phantom_refs(true); // need to comment this in if you use main
        Options.v().set_whole_program(true); // need to comment this in if you use main
        Options.v().set_include_all(true); // need to comment this in if you use main

        Options.v().set_ignore_dex_overflow(true);

        List<String> excludeList = new LinkedList<String>();
        excludeList.add("java.*");
        excludeList.add("sun.misc.*");
        excludeList.add("android.*");
        excludeList.add("com.android.*");
        excludeList.add("dalvik.system.*");
        excludeList.add("org.apache.*");
        excludeList.add("soot.*");
        excludeList.add("javax.servlet.*");
        excludeList.add("dalvik.*");
        excludeList.add("kotlin.*");
        excludeList.add("androidx.*");
        excludeList.add("kotlinx.*");
        Options.v().set_exclude(excludeList);
        Options.v().set_no_bodies_for_excluded(true);
        Scene.v().loadNecessaryClasses();

    }

    public static void setupSootInstrumentation(AppContext appContext) {
        G.reset();

        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_output_format(Options.output_format_dex);

        Options.v().set_android_jars(Config.androidJarPath);
        Options.v().set_process_dir(Collections.singletonList(appContext.getAbsolutePath())); // maybe need to comment this in if you use set_process_multiple_dex
        Options.v().set_output_dir(Paths.get(Config.outputDir, appContext.getPackageName(), "instrumented").toString());
        Options.v().set_process_multiple_dex(true);
        Options.v().set_prepend_classpath(true);
        Options.v().set_soot_classpath("./libs/rt.jar");
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_include_all(true);
        Options.v().set_ignore_dex_overflow(true);
        Scene.v().loadNecessaryClasses();
    }

    /**
     * Setup Soot for the given apk file.
     * @param apkFilePath Path to the apk file
     * @param outputFilePath Path to the output file
     * @param androidJarPath Path to the android jar file
     */
    @Deprecated
    public static void setupSoot(AppContext appContext, String androidJarPath) {

        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_output_format(Options.output_format_dex);
        Options.v().set_android_jars(androidJarPath);
        Options.v().set_process_dir(Collections.singletonList(appContext.getAbsolutePath())); // maybe need to comment this in if you use set_process_multiple_dex
        Options.v().set_output_dir(Paths.get(Config.outputDir, appContext.getPackageName(), "instrumented").toString());
        //Options.v().set_validate(true);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_prepend_classpath(true);
        Options.v().set_soot_classpath("./libs/rt.jar");

        /*Options.v().set_keep_line_number(true);
        Options.v().set_keep_offset(true);
        Options.v().setPhaseOption("jb", "use-original-names:true");*/

        Options.v().set_allow_phantom_refs(true); // need to comment this in if you use main
        Options.v().set_whole_program(true); // need to comment this in if you use main
        Options.v().set_include_all(true); // need to comment this in if you use main

        Options.v().set_ignore_dex_overflow(true);

        Scene.v().addBasicClass("java.io.PrintStream", SootClass.SIGNATURES);
        Scene.v().addBasicClass("java.lang.System",SootClass.SIGNATURES);

        List<String> excludeList = new LinkedList<String>();
        excludeList.add("java.*");
        excludeList.add("sun.misc.*");
        excludeList.add("android.*");
        excludeList.add("com.android.*");
        excludeList.add("dalvik.system.*");
        excludeList.add("org.apache.*");
        excludeList.add("soot.*");
        excludeList.add("javax.servlet.*");
        excludeList.add("dalvik.*");
        excludeList.add("kotlin.*");
        excludeList.add("androidx.*");
        excludeList.add("kotlinx.*");
        Options.v().set_exclude(excludeList);
        Options.v().set_no_bodies_for_excluded(true);
        //Options.v().set_allow_phantom_refs(true);
        //Options.v().set_whole_program(true);
        //String[] args = new String[] {"-process-dir", Config.apkFilePath};
        Scene.v().loadNecessaryClasses();

    }

    @Deprecated
    public static SetupApplication setupSootPlusFlowDroid(AppContext appContext) {
        setupSoot(appContext, Config.androidJarPath);

        InfoflowAndroidConfiguration configuration = new InfoflowAndroidConfiguration();
        configuration.setSootIntegrationMode(InfoflowAndroidConfiguration.SootIntegrationMode.UseExistingInstance);
        configuration.setCodeEliminationMode(InfoflowAndroidConfiguration.CodeEliminationMode.NoCodeElimination);
        configuration.getAnalysisFileConfig().setTargetAPKFile(appContext.getAbsolutePath());
        configuration.setExcludeSootLibraryClasses(true);

        SetupApplication app = new SetupApplication(configuration);
        return app;
    }



    @Deprecated
    public static MySetupApplication setupFlowDroid(String packageName, String apkFilePath, String androidJarPath) {
        InfoflowAndroidConfiguration configuration = new InfoflowAndroidConfiguration();
        configuration.getAnalysisFileConfig().setTargetAPKFile(apkFilePath);
        configuration.getAnalysisFileConfig().setAndroidPlatformDir(Config.androidJarPath);
        configuration.setCodeEliminationMode(InfoflowAndroidConfiguration.CodeEliminationMode.NoCodeElimination);
        configuration.setCallgraphAlgorithm(InfoflowAndroidConfiguration.CallgraphAlgorithm.SPARK);
        //configuration.getAnalysisFileConfig().setOutputFile(OutputUtil.getInstrumentedApkPath(packageName));
        configuration.setMergeDexFiles(true); // equivalent to Options.v().set_process_multiple_dex(true);
        configuration.setEnableReflection(true);
        String appOutputDirectory = Paths.get(Config.outputDir, packageName).toAbsolutePath().toString();
        configuration.getCallbackConfig().setCallbacksFile(Paths.get(appOutputDirectory, "callbacks.txt").toString());
        configuration.getCallbackConfig().setSerializeCallbacks(true);

        // Since we want to serialize the callbacks, we need to make sure that the out directory for the current app exists
        FileUtil.createDirectoryIfNotExists(appOutputDirectory);


        // If we don't call configuration.setWriteOutputFiles(true), then then Options.v().set_output_format(Options.output_format_none) is used
        // If we do, Options.v().set_output_format(Options.output_format_jimple) is used

        MySetupApplication app = new MySetupApplication(configuration);
        /*app.setSootConfig((options, config) -> {
            // If used, base it on soot.jimple.infoflow.android.config.SootConfigForAndroid
            Options.v().set_keep_line_number(true);
            Options.v().set_keep_offset(true);
            Options.v().setPhaseOption("jb", "use-original-names:true");

        });*/
        return app;

    }
}
