package edu.smu.backdroid;

import edu.smu.backdroid.analysis.ClassWorker;
import edu.smu.backdroid.analysis.MethodWorker;
import edu.smu.backdroid.structure.ParaContainer;
import edu.smu.backdroid.structure.ResultContainer;
import edu.smu.backdroid.structure.TrackContainer;
import edu.smu.backdroid.util.CLI;
import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyError;
import edu.smu.backdroid.util.MyUtil;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import soot.Body;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.SootMethodRef;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.CallGraphBuilder;
import soot.jimple.toolkits.callgraph.Sources;

public class PortDetector {
    
    public static String DEXDUMPlog;
    
    public static String DEX2JARfile;
    
    public static String APKfile;
    
    public static String APKprefix;
    
    public static String PKGname;
    
    public static String PKGmust;
    
    public static String PREFIXname;
    
    public static int DETECTtype;
    
    public static Set<String> apiClassSet;
    
    /**
     * the main function of PortDetector
     * 
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        /*
         * resolve arguments
         */
        Options options = new CLI().getOptions();
        
        if (args.length == 0) { //at least one argument
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("PortDetector", options);
            errorHandle(MyError.NoArgus, null);
        }
        else {
            int exitcode = resolveArgus(options, args);
            if (exitcode != 0) errorHandle(exitcode, null);
        }
        
        /**
         * set dex2jar file into the class path
         * 
         * Soot after 2.5 now would not automatically set class path from --cp
         * @see https://github.com/Sable/soot/issues/505
         */
        // Only has "/usr/lib/jvm/java-8-oracle/jre/lib/rt.jar" now
        String classpath = Scene.v().getSootClassPath();
        // A strange bug when run python grepPort.py in the background
        if (classpath.equals("null")) {
            // TODO I use Java 7 (Open JDK) to compile, but use Java 8 (Oracle) to run
            Scene.v().setSootClassPath("/usr/lib/jvm/java-8-oracle/jre/lib/rt.jar");
        }
        Scene.v().extendSootClassPath(DEX2JARfile);
        Scene.v().extendSootClassPath("../lib/android_v25.jar");
        Scene.v().extendSootClassPath("../lib/classes-2.3.4_r1.jar");
        Scene.v().extendSootClassPath("../lib/gapi-16.jar");
        
        Scene.v().extendSootClassPath("../lib/android-support-v13.jar");
        Scene.v().extendSootClassPath("../lib/android-support-v7-appcompat.jar");
        Scene.v().extendSootClassPath("../lib/android-support-v7-cardview.jar");
        Scene.v().extendSootClassPath("../lib/android-support-v7-gridlayout.jar");
        Scene.v().extendSootClassPath("../lib/android-support-v7-mediarouter.jar");
        Scene.v().extendSootClassPath("../lib/android-support-v7-palette.jar");
        Scene.v().extendSootClassPath("../lib/android-support-v7-preference.jar");
        Scene.v().extendSootClassPath("../lib/android-support-v7-recyclerview.jar");
        Scene.v().extendSootClassPath("../lib/android-support-v4.jar");
        
        Scene.v().extendSootClassPath("../lib/android_v28.jar");
        Scene.v().extendSootClassPath("../lib/android_v23.jar");
        Scene.v().extendSootClassPath("../lib/android_v19.jar");
        //Scene.v().setSootClassPath(String.format("%s:%s", DEX2JARfile, classpath));
        
        /*
         * start the analysis
         */
        PortDetector pd = new PortDetector();
        pd.runAnalysis();
        pd.printNewResult();
    }
    
    /**
     * parse arguments
     * 
     * @param options
     * @param args
     * @return
     * @throws ParseException
     */
    private static int resolveArgus(Options options, String args[]) throws ParseException {  
        CommandLineParser parser = new GnuParser();
        CommandLine line = parser.parse(options, args);
        
        PREFIXname = "";
        
        // TODO currently we use grepPort directory to generate dexdump and dex2jar files
        // %s is the name of ApkPrefix
        if (line.hasOption("a")) {
            APKprefix = line.getOptionValue("a");
            DEXDUMPlog = String.format("%s_dexdump.log", APKprefix);
            DEX2JARfile = String.format("%s_dex2jar.jar", APKprefix);
            APKfile = String.format("%s.apk", APKprefix);
            PREFIXname = APKprefix;
            DETECTtype = MyConstant.DETECT_CRYPTO;
        }
        else {
            return MyError.ResolveArgus;
        }
        
        if (line.hasOption("p")) {
            PKGname = line.getOptionValue("p");
            PREFIXname = PKGname;
        }
        
        if (PKGname != null)
            PKGmust = PortDetector.PKGname;
        else
            PKGmust = PortDetector.APKprefix;
        
        if (line.hasOption("r")) {
            MyConstant.CURRENTRANK = Integer.parseInt(line.getOptionValue("r"));
        }
        
        if (line.hasOption("t")) {
            String type = line.getOptionValue("t");
            if (type.equals("OPort") || type.equals("OPORT") || type.equals("OpenPort")) {
                DETECTtype = MyConstant.DETECT_OPENPORT;
            } else if (type.equals("Crypto") || type.equals("CRYPTO") || type.equals("crypto")) {
                DETECTtype = MyConstant.DETECT_CRYPTO;
            }
        }
        
        return 0;
    }
    
    /**
     * handle errors 
     * 
     * @param myerror
     * @param e
     */
    public static void errorHandle(int myerror, Exception e) {
        System.err.print("ERROR: ");
        
        switch (myerror) {
            case MyError.ResolveArgus:
                System.err.println("resolve arguments failed");
                break;
                
            case MyError.NoArgus:
                System.err.println("no arguments provided");
                break;
                
            default:
                System.err.println("unknown");
                break;
        }
        
        // exception
        if (e != null) e.printStackTrace();
        
        System.exit(myerror);
    }
    
    /**
     * A list of TrackContainer.
     * 
     * The core data structure to save all we need, both result and working list
     */
    private List<TrackContainer> tracklist;
    
    public static Set<ResultContainer> ResultSet;
    
    static {
        ResultSet = new HashSet<ResultContainer>();
    }
    
    /**
     * construct a PortDetector
     */
    public PortDetector() {
        this.tracklist = new ArrayList<TrackContainer>();        
    }
    
    /**
     * Begin the real analysis for a SootClass
     * 
     * @param mclass
     * @throws Exception 
     */
    public void runAnalysis() throws Exception {
        /*
         * parse dexdump
         */
        String cmdcontent = "";
        
        if (DETECTtype == MyConstant.DETECT_CRYPTO) {
            cmdcontent = String.format("cat %s " +
                    "| grep -e \"Ljavax/crypto/Cipher;.getInstance:(\" " +
                    "-e \"Lorg/apache/http/conn/ssl/SSLSocketFactory;.setHostnameVerifier:(\" " +
                    "-e \"Ljavax/net/ssl/HttpsURLConnection;.setHostnameVerifier:(\" " +
                    "-e \"Class descriptor\" " +
                    "| grep -B 1 -e \"Ljavax/crypto/Cipher;.getInstance:(\" " +
                    "-e \"Lorg/apache/http/conn/ssl/SSLSocketFactory;.setHostnameVerifier:(\" " +
                    "-e \"Ljavax/net/ssl/HttpsURLConnection;.setHostnameVerifier:(\" " +
                    "| grep \"Class descriptor\" " +
                    "| grep -o \"L.*;\"", DEXDUMPlog);
        }
        else if (DETECTtype == MyConstant.DETECT_OPENPORT) {
            cmdcontent = String.format("cat %s " +
                    "| grep -e \"Ljava/net/ServerSocket;.<init>:(I\" " +
                    "-e \"Ljava/net/ServerSocket;.bind:(\" " +
                    "-e \"Ljavax/net/ssl/SSLServerSocket;.<init>:(I\" " +
                    "-e \"Ljavax/net/ServerSocketFactory;.createServerSocket:(I\" " +
                    "-e \"Class descriptor\" " +
                    "| grep -B 1 -e \"Ljava/net/ServerSocket;.<init>:(I\" " +
                    "-e \"Ljava/net/ServerSocket;.bind:(\" " +
                    "-e \"Ljavax/net/ssl/SSLServerSocket;.<init>:(I\" " +
                    "-e \"Ljavax/net/ServerSocketFactory;.createServerSocket:(I\" " +
                    "| grep \"Class descriptor\" " +
                    "| grep -o \"L.*;\"", DEXDUMPlog);
        }
        
        MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                MyConstant.ForwardPrefix, cmdcontent), MyConstant.DEBUG);
        List<String> classnames = MyUtil.grepDexDumpLogForClass(cmdcontent);
        
        /*
         * set soot options
         * TODO put here?
         */
        soot.options.Options.v().set_whole_program(true); //must before loadClassAndSupport()
        MyUtil.printlnOutput(String.format("Soot class path: %s",
                Scene.v().getSootClassPath()),
                MyConstant.DEBUG);
        
        /*
         * Load android API classes
         */
        if (!classnames.isEmpty()) {
            FileInputStream fileIn = new FileInputStream(MyConstant.dumpClassSer);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            apiClassSet = (Set<String>) in.readObject();
        }
        
        /*
         * run ClassWorker for each class
         */
        for (String classname : classnames) {
            MyUtil.printlnOutput("*** Analyze class: "+classname, MyConstant.INFO);
            ClassWorker classworker = new ClassWorker(this.tracklist);
            SootClass mclass = ClassWorker.loadClass(classname);
            classworker.analyzeClass(mclass);
        }
    }
    
    public void printNewResult() {
        StringBuilder sb = new StringBuilder();
        
        /*
         * The prefix
         */
        sb.append("[BackResult]");
        sb.append(PKGmust);
        
        /*
         * If no result
         */
        if (ResultSet.isEmpty()) {
            sb.append(MyConstant.MiddleWord);
            sb.append(MyConstant.NULL_RES);
            MyUtil.printlnOutput(sb.toString());
            return;
        }
        
        /*
         * Otherwise, have result
         */
        for (ResultContainer rescon : ResultSet) {
            String temp = String.format("%s%s%s",
                    sb.toString(), MyConstant.MiddleWord,
                    rescon.toString());
            MyUtil.printlnOutput(temp);
        }
        
        /*
         * Print cmd and mtd cache result
         */
        MyUtil.printlnOutput(String.format("[CmdCache]---%s---%d---%d",
                PKGmust, MyUtil.uniqueCmdNum, MyUtil.cachedCmdNum),
                MyConstant.RELEASE);
        MyUtil.printlnOutput(String.format("[MtdCache]---%s---%d---%d",
                PKGmust, MethodWorker.uniqueMtdNum, MethodWorker.cachedMtdNum),
                MyConstant.RELEASE);
    }
    
    /**
     * But this function cannot merge similar results
     * 
     * @param rescon
     */
    public static void printOneResult(ResultContainer rescon) {
        StringBuilder sb = new StringBuilder();
        
        /*
         * The prefix
         */
        sb.append("[BackOneRes]");
        if (PKGname != null)
            sb.append(PKGname);
        else
            sb.append(APKprefix);
        
        /*
         * One result
         */
        String temp = String.format("%s%s%s",
                sb.toString(), MyConstant.MiddleWord,
                rescon.toString());
        MyUtil.printlnOutput(temp);
    }
    
    /**
     * print the result analyzed by this PortDetector
     * @deprecated
     */
    public void printResult() {
        MyUtil.printlnOutput(this.tracklist.toString());
        MyUtil.printlnOutput("getIsFinished(): "+getIsFinished(), MyConstant.DEBUG);
        
        /*
         * true result
         */
        MyUtil.printOutput("[PortResult]");
        if (PKGname != null)
            MyUtil.printOutput(PKGname+"::");
        else
            MyUtil.printOutput(APKprefix+"::");
        
        int tracksize = this.tracklist.size();
        MyUtil.printOutput(tracksize+"::");
        
        int i = tracksize;
        for (TrackContainer tc : this.tracklist) {
            String finished;
            
            if (tc.getIsFinished())
                finished = "TRUE";
            else {
                finished = "FALSE";
                // for cases under "FALSE", we further distinguish whether it is "STOP"
                if (tc.isUntraceable())
                    finished = "STOP";
            }
            
            MyUtil.printOutput(String.format("%s--%s", tc.getMethodSig(), finished));
            MyUtil.printOutput("{{");
            
            int pcsize = tc.getParaContainers().size();
            int j = pcsize;
            for (ParaContainer pc : tc.getParaContainers()) {
                MyUtil.printOutput(String.format("%s", pc.getResult()));
                if (j > 1) {
                    MyUtil.printOutput(",,");
                    j--;
                }
            }
            
            MyUtil.printOutput("}}");
            if (i > 1) {
                MyUtil.printOutput(";;");
                i--;
            }
        }
    }
    
    /**
     * @return
     * @deprecated
     */
    public boolean getIsFinished() {
        boolean result = true;
        
        for (TrackContainer tc : this.tracklist) {
            if (!tc.getIsFinished()) {
                result = false;
                break;
            }
        }
        
        return result;
    }
    
    /**
     * Test the feasibility
     * 
     * @param mclass
     * @throws IOException
     * @deprecated
     */
    public void Test(SootClass mclass) throws IOException {
        /**
         * A test to generate the call graph
         * 
         * Then the following SootMethod iteration cannot work...
         */
//        SootMethod dummyMain = mclass.getMethodByName("<init>");
//        List<SootMethod> entryPoints = new ArrayList<SootMethod>();
//        entryPoints.add(dummyMain);
//        Scene.v().setEntryPoints(entryPoints);
//        PackManager.v().runPacks();
//        
//        CallGraph cg = Scene.v().getCallGraph();
//        System.out.println("CG: "+cg.toString());
        
        /**
         * Use spark to generate call graph
         */
//        List<SootMethod> entryPoints = new ArrayList<SootMethod>();
//        entryPoints.addAll( EntryPoints.v().methodsOfApplicationClasses() );
//        entryPoints.addAll( EntryPoints.v().implicit() );
//        Scene.v().setEntryPoints(entryPoints); // see https://github.com/Sable/soot/wiki/Using-Soot-with-custom-entry-points
//        
//        //
//        // create a dummy main to call object method
//        //
////        List<String> methodsToCall = new ArrayList<String>();
//////        for (SootMethod m : EntryPoints.v().methodsOfApplicationClasses()) {
//////            methodsToCall.add(m.getSignature());
//////        }
////        methodsToCall.add("<com.kugou.android.dlna.d.b.a: java.util.ArrayList c(com.kugou.android.dlna.d.b.a)>");
////        methodsToCall.add("<com.kugou.android.dlna.d.b.a: com.kugou.android.dlna.d.b.a a(int)>");
////        methodsToCall.add("<com.kugou.android.dlna.d.b.a: void <init>(int)>");
////        DefaultEntryPointCreator entryPointCreator = 
////                new DefaultEntryPointCreator(methodsToCall);
////        Scene.v().setEntryPoints(Collections.singletonList(entryPointCreator.createDummyMain()));
//        
//        //https://ssebuild.cased.de/nightly/soot/doc/soot_options.htm#phase_5_2
//        Map<String, String> options = new HashMap<String, String>();
//        options.put("enabled", "true");
//        options.put("verbose", "true");
//        options.put("on-fly-cg", "true");
//        options.put("set-impl", "bit");
//        SparkOptions sparkoptions = new SparkOptions(options);
//        PointsToAnalysis pa = new PAG(sparkoptions);
//        
//        CallGraphBuilder cgbuilder = new CallGraphBuilder(pa);
//        cgbuilder.build();
//        CallGraph cg = Scene.v().getCallGraph();
        
        /**
         * Use DumbPointerAnalysis, a naive pointer analysis, to generate call graph 
         */
        CallGraphBuilder cgbuilder = new CallGraphBuilder();
        cgbuilder.build();
        CallGraph cg = Scene.v().getCallGraph();
        
        /**
         * loop all methods to find the target method that contains ServerSocket
         */
        List<SootMethod> methods = mclass.getMethods();
        
        for (SootMethod method : methods) {
            MyUtil.printlnOutput("Method: "+method.getSignature(), MyConstant.DEBUG);
            
            Body body = method.retrieveActiveBody();
            //body = Shimple.v().newBody(body);
            
            Iterator<Unit> iter_u = body.getUnits().iterator();;
            while (iter_u.hasNext()) {
                Unit unit = iter_u.next();

                InvokeExpr invokeexpr = null;
                if (unit instanceof InvokeStmt) {
                    InvokeStmt invokestmt = (InvokeStmt) unit;
                    invokeexpr = invokestmt.getInvokeExpr();
                } else if (unit instanceof AssignStmt) {
                    AssignStmt as = (AssignStmt) unit;
                    Value v = as.getRightOp();

                    if (as.containsInvokeExpr()) {
                        invokeexpr = (InvokeExpr) v;
                    }
                }

                if (invokeexpr != null) {
                    SootMethodRef mref = invokeexpr.getMethodRef();
                    String msig = mref.getSignature(); // <com.nupt.stitp.MobileSecService$8:
                                                       // void start()>
                    System.out.println("==> " + msig);
                }
            }
            
            Iterator sources = new Sources(cg.edgesInto(method));
            while (sources.hasNext()) {
                SootMethod src = (SootMethod) sources.next();
                System.out.println("<== "+src.getSignature());
            }
        }
    }

}
