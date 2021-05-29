package edu.smu.testfd;

import java.util.Iterator;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.ParseException;

import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.config.SootConfigForAndroid;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;

/**
 * Refer to
 * https://github.com/secure-software-engineering/FlowDroid/issues/56
 * TestCallGraph in BackDroid source code
 * 
 * Used for a Python script to automatically generate app call graphs
 * 
 * @author Daoyuan
 * @since 2019-03-16
 */
public class GenCallGraph {
    
    public static String APKfile;
    
    // TODO you need to replace this path.
    public static String AndroSDK = "/home/dao/software/android-sdk-linux_x86/platforms";

    /**
     * @param args
     * @throws ParseException 
     */
    public static void main(String[] args) throws ParseException {
        /*
         * resolve arguments
         */
        org.apache.commons.cli.Options options = new CLI().getOptions();
        if (args.length == 0) { //at least one argument
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("GenCallGraph", options);
            System.exit(-1);
        }
        CommandLineParser parser = new GnuParser();
        CommandLine line = parser.parse(options, args);
        if (line.hasOption("a"))
            APKfile = line.getOptionValue("a");
        else
            System.exit(-1);
        
        /**
         * Initialize Soot
         */
        /*
         * com.kugou.android-6362.apk
         * 064_com.asus.filemanager.apk
         * weibo_1920.apk
         * 
         * cn.wps.moffice_eng.apk: exception after 11min (2.5.1) and 7m (2.7.1), Attempt to create VarNode of type short
         * com.kugou.android.apk: killed after 168m (4G), killed after 801m (12G)
         * com.dropbox.android.apk: 5m1.224s (12G), 5m41s (4G)
         * com.grabtaxi.passenger.apk: 29m13.426s
         */
        SetupApplication analyzer = new SetupApplication(AndroSDK, APKfile);
        
        /*
         * https://github.com/secure-software-engineering/FlowDroid/issues/44
         * 
         */
        //analyzer.setCallbackFile("../lib/AndroidCallbacks.txt");
        analyzer.getConfig().setSootIntegrationMode(InfoflowAndroidConfiguration.SootIntegrationMode.CreateNewInstace);
        analyzer.getConfig().setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.GEOM);
        analyzer.getConfig().setMergeDexFiles(true);
        //analyzer.getConfig().setOneComponentAtATime(false);
        
        /*
         * https://github.com/Sable/soot/issues/772
         * https://github.com/Sable/soot/wiki/Using-Geometric-Encoding-based-Context-Sensitive-Points-to-Analysis-(geomPTA)
         */
        SootConfigForAndroid sootConfig = new SootConfigForAndroid() {
            @Override
            public void setSootOptions(Options options, InfoflowConfiguration config) {
                // we need to specify soot options here since FlowDroid resets them
                super.setSootOptions(options, config);
                //options.set_process_multiple_dex(true);
                //options.set_whole_program(true);
                //options.set_allow_phantom_refs(true);
                //options.setPhaseOption("cg.spark", "geom-runs:2");
            }
        };
        analyzer.setSootConfig(sootConfig);
        
        analyzer.constructCallgraph();
        
        // Print overall graph
//        System.out.println("Call graph:");
//        System.out.println(Scene.v().getCallGraph());
//        
//        // Iterate over the callgraph
//        for (Iterator<Edge> edgeIt = Scene.v().getCallGraph().iterator(); edgeIt.hasNext(); ) {
//            Edge edge = edgeIt.next();
//            
//            SootMethod smSrc = edge.src();
//            Unit uSrc = edge.srcStmt();
//            SootMethod smDest = edge.tgt();
//            
//            System.out.println("Edge from " + uSrc + " in " + smSrc + " to " + smDest);
//        }
    }

}
