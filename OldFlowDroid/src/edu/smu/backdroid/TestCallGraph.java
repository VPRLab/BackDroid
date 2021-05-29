package edu.smu.backdroid;

import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import soot.PackManager;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.source.AndroidSourceSinkManager.LayoutMatchingMode;
import soot.options.Options;

public class TestCallGraph {
    
    // TODO you need to replace this path.
    public static String AndroSDK = "/home/dao/software/android-sdk-linux_x86/platforms";
    
    /**
     * https://github.com/secure-software-engineering/soot-infoflow-android/issues/76
     * 
     * Quite slow and consume many memories
     * 
     * @param args
     * @throws XmlPullParserException 
     * @throws IOException 
     */
    public static void main(String[] args) throws IOException, XmlPullParserException {
        //
        // com.facebook.orca-49249863-v104.0.0.13.69.apk: 0m38.423s
        // uk.co.sevendigital.android-91.apk: 2m44.440s
        // But their call graph is 0 or is very limited.
        // 
        // com.kugou.android-6362.apk: 24m2.394s
        // com.kugou.android-6362.apk: OutOfMemoryError after 40m
        // Also tested cn.wps.moffice_eng.apk
        //
        SetupApplication app = new SetupApplication
                (AndroSDK, "../test/com.kugou.android.apk");
        
        app.calculateSourcesSinksEntrypoints("../lib/SourcesAndSinks.txt");
        soot.G.reset();

        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(Collections.singletonList("../test/com.kugou.android.apk"));
        Options.v().set_android_jars(AndroSDK);
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_output_format(Options.output_format_class);
        Options.v().setPhaseOption("cg.spark", "on");
        
        // do not merge variables (causes problems with PointsToSets)
        //Options.v().setPhaseOption("jb.ulp", "off");
        
        /**
         * Set configuration object
         * 
         * @see soot-inforflow-android Test parseAdditionalOptions
         */
//        InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
//        config.setCallgraphAlgorithm(CallgraphAlgorithm.CHA);
//        config.setEnableCallbacks(false);
//        config.setLayoutMatchingMode(LayoutMatchingMode.NoMatch);
//        app.setConfig(config);

        Scene.v().loadNecessaryClasses();

        SootMethod entryPoint = app.getEntryPointCreator().createDummyMain();
        Options.v().set_main_class(entryPoint.getSignature());
        Scene.v().setEntryPoints(Collections.singletonList(entryPoint));
        //System.out.println(entryPoint.getActiveBody());

        //PackManager.v().getPack("cg").apply();
        PackManager.v().runPacks();
        System.out.println("Call graph:"); 
        System.out.println(Scene.v().getCallGraph()); 
    }

}
