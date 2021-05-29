package edu.smu.backdroid.analysis;

import edu.smu.backdroid.PortDetector;
import edu.smu.backdroid.graph.BDG;
import edu.smu.backdroid.graph.BDGToDotGraph;
import edu.smu.backdroid.structure.CallerContainer;
import edu.smu.backdroid.structure.ParaContainer;
import edu.smu.backdroid.structure.TaintContainer;
import edu.smu.backdroid.structure.TrackContainer;
import edu.smu.backdroid.structure.VLMContainer;
import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import soot.Body;
import soot.Local;
import soot.PatchingChain;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceFieldRef;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.ParameterRef;
import soot.jimple.ReturnStmt;
import soot.jimple.StaticFieldRef;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.CallGraphBuilder;
import soot.jimple.toolkits.callgraph.Edge;
import soot.util.dot.DotGraph;

public class ClassWorker {
    
    private static Map<String, Boolean> cacheClsSearch = new HashMap<String, Boolean>();
    
    private static Set<String> allNonReachableMsig = new HashSet<String>();
    
    /**
     * a list of TrackContainer, to save results
     */
    private List<TrackContainer> tracklist;
    
    public ClassWorker(List<TrackContainer> tracklist) {
        this.tracklist = tracklist;
    }
    
    /**
     * load a class into Soot and return SootClass
     * 
     * TODO avoid repeat loading? So optimize it
     * 
     * @param classname
     * @return
     */
    public static SootClass loadClass(String classname) {
        /*
         * setApplicationClass:
         * Makes this class an application class.
         */
        SootClass mclass = null;
        try {
            mclass = Scene.v().loadClassAndSupport(classname);
            //mclass = Scene.v().loadClass(classname, SootClass.BODIES);
            
            // must add the following, otherwise, the call graph cannot backward
//            SootClass appclass = Scene.v().loadClassAndSupport("com.kugou.framework.service.KugouPlaybackService");
//            appclass.setApplicationClass();
//            
//            appclass = Scene.v().loadClassAndSupport("com.kugou.android.dlna.a.c");
//            appclass.setApplicationClass();
            
        } catch (RuntimeException e) {
            e.printStackTrace();
            
            String eMsg = e.getMessage();
            if (eMsg.contains(classname)) {
                System.err.println("0ERROR: " + e.getMessage()); //class cannot be found in the beginning
            }
            else {
                System.err.println("1ndWARN: " + e.getMessage()); //loadClassAndSupport has error
                
                try {
                    mclass = Scene.v().loadClass(classname, SootClass.BODIES);
                    
                } catch (RuntimeException ee) {
                    System.err.println("2ndWARN: " + e.getMessage()); //loadClass has error
                    
                    soot.options.Options.v().set_allow_phantom_refs(true);
                    mclass = Scene.v().loadClass(classname, SootClass.BODIES);
                }
            }
        }
        mclass.setApplicationClass();
        
        Scene.v().loadBasicClasses();   //TODO necessary?
        //Scene.v().loadNecessaryClasses(); //another choice, which must be used after loadClassAndSupport
        //
        // TODO hu.tagsoft.ttorrent.lite-10000068
        // Exception in thread "main" java.lang.IllegalStateException: Have to call loadDynamicClasses() first!
        //
        Scene.v().loadDynamicClasses();
        
        return mclass;
    }
    
    /**
     * analyze one SootClass
     * 
     * TODO !!! should also pinpoint the target method to save time
     * 
     * @param mclass
     */
    public void analyzeClass(SootClass mclass) {
        /*
         * loop all methods to find the target method that contains ServerSocket
         */
        Iterator<SootMethod> method_iter = mclass.methodIterator();
        while (method_iter.hasNext()) {
            SootMethod method = method_iter.next();
            
            if (!method.isConcrete())
                continue;
            
            Body body = MyUtil.retrieveActiveSSABody(method);
            if (body == null)
                continue;
            
            TrackContainer track = null;
            BDG bdg = null;
            
            // TODO address performance problem for methods within the same method
            Iterator<Unit> iter_u = body.getUnits().iterator();
            while (iter_u.hasNext()) {
                Unit unit = iter_u.next();

                if (unit instanceof InvokeStmt || unit instanceof AssignStmt) {
                    String unitstr = unit.toString();
                    String methodSig = null;
                    
                    if (unitstr.contains(MyConstant.ServerSocketKeyword)) {
                    //no longer use ServerSocketPrefix
                        if (unitstr.contains(MyConstant.ServerSocketInit1))
                            methodSig = MyConstant.ServerSocketInit1;
                        else if (unitstr.contains(MyConstant.ServerSocketInit2))
                            methodSig = MyConstant.ServerSocketInit2;
                        else if (unitstr.contains(MyConstant.ServerSocketInit3))
                            methodSig = MyConstant.ServerSocketInit3;
                        else if (unitstr.contains(MyConstant.ServerSocketBind1))
                            methodSig = MyConstant.ServerSocketBind1;
                        else if (unitstr.contains(MyConstant.ServerSocketBind2))
                            methodSig = MyConstant.ServerSocketBind2;
                        else if (unitstr.contains(MyConstant.SSLServerSocketInit1))
                            methodSig = MyConstant.SSLServerSocketInit1;
                        else if (unitstr.contains(MyConstant.SSLServerSocketInit2))
                            methodSig = MyConstant.SSLServerSocketInit2;
                        else if (unitstr.contains(MyConstant.SSLServerSocketInit3))
                            methodSig = MyConstant.SSLServerSocketInit3;
                        else if (unitstr.contains(MyConstant.ServerSocketFactoryCreate1))
                            methodSig = MyConstant.ServerSocketFactoryCreate1;
                        else if (unitstr.contains(MyConstant.ServerSocketFactoryCreate2))
                            methodSig = MyConstant.ServerSocketFactoryCreate2;
                        else if (unitstr.contains(MyConstant.ServerSocketFactoryCreate3))
                            methodSig = MyConstant.ServerSocketFactoryCreate3;
                        
                        if (PortDetector.DETECTtype != MyConstant.DETECT_OPENPORT)
                            methodSig = null;
                        
                    } else if (unitstr.contains(MyConstant.HostnameVerifierKeyword)
                            || unitstr.contains(MyConstant.CipherInstanceKeyword)) {
                        
                        if (unitstr.contains(MyConstant.CipherGetInstance))
                            methodSig = MyConstant.CipherGetInstance;
                        else if (unitstr.contains(MyConstant.FactorySetHostnameVerifier))
                            methodSig = MyConstant.FactorySetHostnameVerifier;
                        else if (unitstr.contains(MyConstant.URLSetHostnameVerifier))
                            methodSig = MyConstant.URLSetHostnameVerifier;
                        
                        if (PortDetector.DETECTtype != MyConstant.DETECT_CRYPTO)
                            methodSig = null;
                    }
                    
                    if (methodSig != null) {
                        String msig = method.getSignature();
                        String mtempsig = String.format("<%s: %s>", 
                                mclass.getName(), method.getName());
                        
                        /*
                         * First quickly search whether this class should be analyzed
                         */
                        if (false) {
                            boolean isAnalyze = isAnalyzeThisClass(mclass);
                            if (!isAnalyze) {
                                continue;
                            }
                        }
                        /*
                         * Just exclude those non-reachable methods
                         */
                        if (allNonReachableMsig.contains(mtempsig)) {
                            MyUtil.printlnOutput(String.format("[BackSink]%s---%s---skipped---NotReachable",
                                    PortDetector.PKGmust, msig), MyConstant.RELEASE);
                            continue;
                        }
                        
                        MyUtil.printlnOutput(String.format("%s Method: %s has '%s'", 
                                MyConstant.CriticalPrefix, msig, unitstr), MyConstant.DEBUG);
                        
                        /*
                         * Backward analysis to build BDG
                         */
                        track = new TrackContainer(methodSig);
                        this.tracklist.add(track);
                        bdg = new BDG(methodSig);   //TODO add into the list
                        
                        boolean isReachable = MethodWorker.v().backwardSlicing(unit, body, bdg);
                        if (!isReachable) {
                            allNonReachableMsig.add(mtempsig);
                            MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---NotReachable",
                                    PortDetector.PKGmust, msig), MyConstant.RELEASE);
                        } else {
                            MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---REACHABLE",
                                    PortDetector.PKGmust, msig), MyConstant.RELEASE);
                        }
                        
                        /*
                         * Print BDG
                         */
                        if (MyConstant.CURRENTRANK <= MyConstant.RELEASE) {
                            BDGToDotGraph converter = new BDGToDotGraph();
                            DotGraph dotg = converter.drawBDG(bdg, mclass.getName());
                            dotg.plot(PortDetector.PREFIXname + "_"
                                        +mclass.getName()+"_"
                                        +method.getName()+"_BDG.dot");
                        }
                        
                        /*
                         * Forward analysis to obtain parameter values
                         */
                        new ForwardWorker(bdg).analyzeBDG();
                    }
                }
            }
            
        }//--end of analysis of one method
    }
    
    public boolean isAnalyzeThisClass(SootClass mclass) {
        boolean isAnalyze = false;
        
        /*
         * Obtain the searched class name
         * Only two or three portions, same as the root class name 
         */
        String cls_name = mclass.getName();
        String cls_search = MyUtil.generateClsSearchFromJava(cls_name);
        
        /*
         * Check the cache using cls_search: "Lcom/connectsdk/service"
         */
        MyUtil.printlnOutput(String.format("%s cls_search is %s for %s", 
                MyConstant.NormalPrefix, cls_search, cls_name), MyConstant.DEBUG);
        // If the first search is not a name, we can use cls_search as the key
        if (cacheClsSearch.containsKey(cls_name)) {
            Boolean value = cacheClsSearch.get(cls_name);
            
            if (value.booleanValue() == true)
                MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---ByCache",
                        PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
            else
                MyUtil.printlnOutput(String.format("[BackSink]%s---%s---skipped---ByCache",
                        PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
            
            return value.booleanValue();
        }
        
        /*
         * Generate the DEX format of root class set
         */
        if (!ManifestWorker.v().isAnalyzed())
            ManifestWorker.v().runAnalysis();
        
        Set<String> rootClsDexSet = new HashSet<String>();
        Set<String> rootClsSet = ManifestWorker.v().getRootClsSet();
        for (String rootcls_java : rootClsSet) {
            String rootcls_dex = MyUtil.transformIntoDexDumpValueType(rootcls_java);
            rootcls_dex = rootcls_dex.substring(0, rootcls_dex.length() - 1);
            rootClsDexSet.add(rootcls_dex);
        }
        
        /*
         * First see whether it is directly contained in manifest
         * cls_search Lcom/lge/app1/fota match manifest name Lcom/lge/app1
         */
        for (String rootcls_dex : rootClsDexSet) {
            if (MyUtil.hasOverlapInTwoString(cls_search, rootcls_dex)) {
                MyUtil.printlnOutput(String.format(
                        "%s cls_search %s match manifest name %s", 
                        MyConstant.NormalPrefix, cls_search, rootcls_dex),
                        MyConstant.DEBUG);
                isAnalyze = true;
                // We can directly return now.
                MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---Directly",
                        PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
                cacheClsSearch.put(cls_name, new Boolean(isAnalyze));
                return isAnalyze;
            }
        }
        
        /*
         * To avoid repeated searches
         * And we should not use rootClsDexSet now
         */
        Set<String> searchedClsSet = new HashSet<String>();
        Set<String> maniCompDexSet = ManifestWorker.v().getManiCompDexSet();
        
        /*
         * The first-time search of contained classes
         * The first should be cls_name instead of cls_search, because it is fixed...
         */
        Set<String> first_cls_searches = new HashSet<String>();
        Set<String> first_cls_names = new HashSet<String>();
        if (!isAnalyze) {
            // First generate cls_search
            String cls_name_dex = MyUtil.transformIntoDexDumpValueType(cls_name);
            List<String> contained_clses_dex = MyUtil.searchContainedClass(cls_name_dex);
            searchedClsSet.add(cls_name_dex);
            
            for (String contained_cls_dex : contained_clses_dex) {
                // Then check
                if (maniCompDexSet.contains(contained_cls_dex)) {
                    // cls_search Lcom/connectsdk/service use first search Lcom/connectsdk/service 
                    // to match manifest name Lcom/lge/app1/activity/MainActivity;
                    MyUtil.printlnOutput(String.format(
                            "%s cls_search %s use first class %s to match manifest name %s", 
                            MyConstant.NormalPrefix, cls_search, cls_name_dex, contained_cls_dex),
                            MyConstant.WARN);
                    MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---FIRST",
                            PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
                    isAnalyze = true;
                    break;
                }
                // For later potential usage
                String contained_cls_search = MyUtil.generateClsSearchFromDex(contained_cls_dex);
                first_cls_searches.add(contained_cls_search);
                // Or
                first_cls_names.add(contained_cls_dex);
            }
        }
        
        /*
         * The following cases use cls_search to avoid too much searches
         * The second-time search of contained classes
         */
        Set<String> second_cls_searches = new HashSet<String>();
        if (!isAnalyze) {
            if (first_cls_names.size() <= 10) {
                for (String first_cls_name : first_cls_names) {
                    if (searchedClsSet.contains(first_cls_name))
                        continue;
                    
                    // First generate cls_search
                    List<String> contained_clses_dex = MyUtil.searchContainedClass(first_cls_name);
                    searchedClsSet.add(first_cls_name);
                    
                    for (String contained_cls_dex : contained_clses_dex) {
                        // Then check
                        if (maniCompDexSet.contains(contained_cls_dex)) {
                            // cls_search Lcom/connectsdk/service use second search Lcom/connectsdk/service 
                            // to match manifest name Lcom/lge/app1/activity/MainActivity;
                            MyUtil.printlnOutput(String.format(
                                    "%s cls_search %s use second class %s to match manifest name %s", 
                                    MyConstant.NormalPrefix, cls_search, first_cls_name, contained_cls_dex),
                                    MyConstant.WARN);
                            MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---SECOND",
                                    PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
                            isAnalyze = true;
                            break;
                        }
                        // For later potential usage
                        String contained_cls_search = MyUtil.generateClsSearchFromDex(contained_cls_dex);
                        second_cls_searches.add(contained_cls_search);
                    }
                    // Finally break
                    if (isAnalyze)
                        break;
                }
            } else {
                for (String first_cls_search : first_cls_searches) {
                    if (searchedClsSet.contains(first_cls_search))
                        continue;
                    
                    // First generate cls_search
                    List<String> contained_clses_dex = MyUtil.searchContainedClass(first_cls_search);
                    searchedClsSet.add(first_cls_search);
                    
                    for (String contained_cls_dex : contained_clses_dex) {
                        // Then check
                        if (maniCompDexSet.contains(contained_cls_dex)) {
                            // cls_search Lcom/connectsdk/service use second search Lcom/connectsdk/service 
                            // to match manifest name Lcom/lge/app1/activity/MainActivity;
                            MyUtil.printlnOutput(String.format(
                                    "%s cls_search %s use second search %s to match manifest name %s", 
                                    MyConstant.NormalPrefix, cls_search, first_cls_search, contained_cls_dex),
                                    MyConstant.WARN);
                            MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---SECOND",
                                    PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
                            isAnalyze = true;
                            break;
                        }
                        // For later potential usage
                        String contained_cls_search = MyUtil.generateClsSearchFromDex(contained_cls_dex);
                        second_cls_searches.add(contained_cls_search);
                    }
                    // Finally break
                    if (isAnalyze)
                        break;
                }
            }
        }
        
        /*
         * The third-time search of contained classes
         */
        Set<String> third_cls_searches = new HashSet<String>();
        if (!isAnalyze) {
            for (String second_cls_search : second_cls_searches) {
                if (searchedClsSet.contains(second_cls_search))
                    continue;
                
                // First generate cls_search
                List<String> contained_clses_dex = MyUtil.searchContainedClass(second_cls_search);
                searchedClsSet.add(second_cls_search);
                
                for (String contained_cls_dex : contained_clses_dex) {
                    // Then check
                    if (maniCompDexSet.contains(contained_cls_dex)) {
                        // cls_search Lcom/unboundid/ldap use third search Lcom/lge/app1 
                        // to match manifest name Lcom/lge/app1/MainApplication;
                        MyUtil.printlnOutput(String.format(
                                "%s cls_search %s use third search %s to match manifest name %s", 
                                MyConstant.NormalPrefix, cls_search, second_cls_search, contained_cls_dex),
                                MyConstant.WARN);
                        MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---THIRD",
                                PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
                        isAnalyze = true;
                        break;
                    }
                    // For later potential usage
                    String contained_cls_search = MyUtil.generateClsSearchFromDex(contained_cls_dex);
                    third_cls_searches.add(contained_cls_search);
                }
                // Finally break
                if (isAnalyze)
                    break;
            }
        }
        
        /*
         * The fourth-time search of contained classes
         * We need to launch the fourth-time search, because of the following example:
         * com.ironhidegames.android.kingdomrush_crittercism.android.c_a_BDG
         */
        Set<String> fourth_cls_searches = new HashSet<String>();
        if (!isAnalyze) {
            for (String third_cls_search : third_cls_searches) {
                if (searchedClsSet.contains(third_cls_search))
                    continue;
                
                // First generate cls_search
                List<String> contained_clses_dex = MyUtil.searchContainedClass(third_cls_search);
                searchedClsSet.add(third_cls_search);
                
                for (String contained_cls_dex : contained_clses_dex) {
                    // Then check
                    if (maniCompDexSet.contains(contained_cls_dex)) {
                        // cls_search Lcrittercism/android use fourth search Lcom/jirbo/adcolony 
                        // to match manifest name Lcom/jirbo/adcolony/AdColonyBrowser;
                        MyUtil.printlnOutput(String.format(
                                "%s cls_search %s use fourth search %s to match manifest name %s", 
                                MyConstant.NormalPrefix, cls_search, third_cls_search, contained_cls_dex),
                                MyConstant.WARN);
                        MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---FOURTH",
                                PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
                        isAnalyze = true;
                        break;
                    }
                    // For later potential usage
                    String contained_cls_search = MyUtil.generateClsSearchFromDex(contained_cls_dex);
                    fourth_cls_searches.add(contained_cls_search);
                }
                // Finally break
                if (isAnalyze)
                    break;
            }
        }
        
        /*
         * The fifth-time search of contained classes
         * jp.gree.marketing.network.NetworkClient---analyzed---FIFTH
         */
        if (!isAnalyze) {
            for (String fourth_cls_search : fourth_cls_searches) {
                if (searchedClsSet.contains(fourth_cls_search))
                    continue;
                
                // First generate cls_search
                List<String> contained_clses_dex = MyUtil.searchContainedClass(fourth_cls_search);
                searchedClsSet.add(fourth_cls_search);
                
                for (String contained_cls_dex : contained_clses_dex) {
                    // Then check
                    if (maniCompDexSet.contains(contained_cls_dex)) {
                        MyUtil.printlnOutput(String.format(
                                "%s cls_search %s use fourth search %s to match manifest name %s", 
                                MyConstant.NormalPrefix, cls_search, fourth_cls_search, contained_cls_dex),
                                MyConstant.WARN);
                        MyUtil.printlnOutput(String.format("[BackSink]%s---%s---analyzed---FIFTH",
                                PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
                        isAnalyze = true;
                        break;
                    }
                }
                // Finally break
                if (isAnalyze)
                    break;
            }
        }
        
        /*
         * Add to the cache
         */
        if (!isAnalyze) {
            MyUtil.printlnOutput(String.format("[BackSink]%s---%s---skipped---ByEnd",
                    PortDetector.PKGmust, cls_name), MyConstant.RELEASE);
        }
        cacheClsSearch.put(cls_name, new Boolean(isAnalyze));
        
        return isAnalyze;
    }
    
    /**
     * We have finished the analysis of a SootMethod.
     * Now we check TrackContainer to determine:
     * 1) parameter backward; Call graph
     * 2) instance field
     * 3) static field
     * 4) return
     * 
     * TODO This should be mainly for parameter tracking
     * TODO Which means we need to handle other cases in difference places
     * 
     * This is a recursive method!
     * 
     * @param method the method we have finished its intra-procedural analysis
     * @param track
     * @deprecated
     */
    public void furtherCheck(TrackContainer track) {
        if (track == null)
            return;
        
        for (ParaContainer pc : track.getParaContainers()) {
            if (pc.getIsFinished())
                continue;
            
            List<TaintContainer> tclist = pc.getCurrentTaints();
            if (tclist == null)
                continue;
            
            for (TaintContainer tc : tclist) {
                Value index = tc.getIndex();
                Value last_v = tc.getTaint();
                
                VLMContainer vlm = pc.getVLMContainer(index);
                SootMethod method = vlm.getCurrentMethod();
                SootClass mclass = method.getDeclaringClass();
                
                MyUtil.printlnOutput("--> Now method: "+method.getSignature(), MyConstant.DEBUG);
                
                /*
                 * 1) Parameter
                 */
                if (last_v instanceof ParameterRef) {
                    ParameterRef pr = (ParameterRef) last_v;
                    int prindex = pr.getIndex();
                    MyUtil.printlnOutput(String.format("--> Parameter: %s, Index: %s, Type: %s",
                            last_v, prindex, pr.getType()), MyConstant.DEBUG);
                    
                    //
                    // Use dexdump to grep which class calls this method
                    // For <init> functions, we can use the full representation for grep
                    // Then load that class, and then build the call graph
                    // Use call graph to resolve the method and that Unit
                    // Transform the parameter, jump to source method, and do intra-procedural analysis again
                    //
                    List<StringBuilder> dexdump_method_sbs = MyUtil.transformIntoDexDumpMethod(method);
                    
                    for (StringBuilder dexdump_method_sb : dexdump_method_sbs) {
                        String dexdump_method = MyUtil.sanitizeSS(dexdump_method_sb.toString());
                        String cmdcontent = String.format("cat %s " +
                                "| grep -e \"%s\" -e \"Class descriptor\" " +
                                "| grep -B 1 -e \"%s\" " +
                                "| grep \"Class descriptor\" " +
                                "| grep -o \"L.*;\"", PortDetector.DEXDUMPlog,
                                dexdump_method, dexdump_method);
                        
                        MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                                MyConstant.NormalPrefix, cmdcontent), MyConstant.DEBUG);
                        List<String> classes = MyUtil.grepDexDumpLogForClass(cmdcontent);
                        for (String tempclass : classes) {
                            MyUtil.printlnOutput(String.format("%s grep class: %s",
                                    MyConstant.NormalPrefix, tempclass), MyConstant.DEBUG);
                            // Add new class to call graph
                            loadClass(tempclass);
                        }
                    }
                    
                    CallGraph cg = getCallGraph();
                    
                    // calculate edges
                    int edgelen = 0;
                    Iterator<Edge> edges = cg.edgesInto(method);
                    while (edges.hasNext()) {
                        Edge edge = edges.next();
                        SootMethod src_method = edge.src();
                        Unit src_unit = edge.srcUnit();
                        String src_method_sig = src_method.getSignature();
                        MyUtil.printlnOutput("<== "+src_method_sig+" at "+src_unit, MyConstant.DEBUG);
                        edgelen++;
                    }
                    
                    // if no edge into the current method
                    if (edgelen == 0) {
                        MyUtil.printlnOutput(MyConstant.CriticalPrefix
                                +" No method comes to "+method.getSignature(), MyConstant.WARN);
                        track.setUntraceable(true);
                    }
                    
                    // record the original VLMContainer index
                    int vlm_oldlen = vlm.getValuelist().size();
                    
                    // real backward tracing
                    int remainedge = edgelen;
                    edges = cg.edgesInto(method);
                    while (edges.hasNext()) {
                        Edge edge = edges.next();
                        SootMethod src_method = edge.src();
                        Unit src_unit = edge.srcUnit();
                        String src_method_sig = src_method.getSignature();
                        MyUtil.printlnOutput("<== Tracing "+src_method_sig+" at "+src_unit, MyConstant.WARN);
                        remainedge--;
                        
                        // special handle app backup case
//                        if (src_method_sig.equals("<mobi.infolife.wifitransfer.TransferServer: " +
//                                "void <init>(int,android.content.Context)>") ||
//                            src_method_sig.equals("<br.com.zeroum.turmadagalinha.webserver.NanoHTTPD: " +
//                            		"void <init>(int)>"))
//                            continue;
                        
                        InvokeExpr src_expr = UnitWorker.v().getInvokeExpr(src_unit);
                        Value para = src_expr.getArg(prindex);//TODO Inconsistency for Shimple and Jimple format? E.g., i0
                        
                        pc.addTaintValue(index, para, src_method); //no split here
                        MethodWorker.v().backwardUnit(src_unit, src_method, track, index);
                        
                        furtherCheck(track);
                        
                        // if we only have the last choice
                        if (remainedge == 0)
                            break;
                        
                        //
                        // TODO better end determination
                        // TODO VLMContainer ends or ParaContainer ends??
                        // TODO Better with ParaContainer, but we currently cannot recover the whole ParaContainer
                        //
                        Value vlm_last = vlm.getValuelist().getLast();
                        if (vlm_last instanceof ParameterRef) {
                            MyUtil.printlnOutput(String.format("%s This path %s ends at an untraceable parameter, %s", 
                                    MyConstant.CriticalPrefix, src_method_sig, vlm_last.toString()), MyConstant.WARN);
                            
                            // recover the original VLMContainer structure
                            vlm.recoverToOld(vlm_oldlen, method);
                            
                            // recover the default isUntraceable variable
                            track.setUntraceable(false);
                        }
                        else {
                            // TODO stop when we have one flow containing result
                            break;
                        }
                    }
                }
                /*
                 * 2) Instance field
                 */
                else if (last_v instanceof InstanceFieldRef) {
                    InstanceFieldRef ifr = (InstanceFieldRef)last_v;
                    Value base = ifr.getBase();
                    MyUtil.printlnOutput(String.format("--> InstanceFieldRef: %s, Base: %s",
                            last_v, base), MyConstant.DEBUG);
                    
                    //
                    // The base can be:
                    // 1) a this variable: r0 := @this: com.kugou.android.dlna.d.b.a;
                    // 2) a parameter variable: r0 := @parameter0: com.afollestad.neuron.Terminal;
                    // see https://ssebuild.cased.de/nightly/soot/javadoc/soot/jimple/IdentityRef.html
                    //
                    
//                    //
//                    // ThisRef does not work here.
//                    // Because base's getClass() is: soot.jimple.internal.JimpleLocal
//                    // base's getType() is: com.kugou.android.dlna.d.b.a
//                    //
//                    String basetype = base.getType().toString();
//                    if (basetype.equals(mclass.getName())) {
//                        MyUtil.printlnOutput("--> It is a this field", MyConstant.DEBUG);
                    
                    if (base instanceof Local) {
                        Body body = method.getActiveBody();
                        boolean isParameter;
                        Local thislocal;
                        /*
                        List<Local> paralocals = body.getParameterLocals(); //NoSuchMethodError in Soot 2.5
                        for (Local paralocal : paralocals) {
                            if (paralocal.getName().equals(((Local) base).getName())) {
                                isParameter = true;
                                break;
                            }
                        }
                        */
                        try {
                            thislocal = body.getThisLocal();//will RuntimeException if no this variable
                            if (thislocal != null && thislocal.getName().equals(((Local) base).getName()))
                                isParameter = false;        //this field
                            else
                                isParameter = true;         //parameter field
                        } catch(Exception e) {
                            isParameter = true;
                        }
                        
                        if (!isParameter) {
                            MyUtil.printlnOutput(String.format("--> %s is a this field", base),
                                    MyConstant.DEBUG);
                            
                            //
                            // previously we have parsed the inside-method. Must no found, otherwise, we will not come here
                            //
                            // now let's just go to <init>(...)
                            // TODO feel like that here we need the forward analysis, because of maybe there are several <init>(...)
                            // TODO we need a dexdump guided forward analysis, to search "this.f()" in com.kugou.android.dlna.d.b.a case
                            //
                            // this is always 'r0', so no need to transform it when we jump to <init>
                            //
                            for (SootMethod temp_method : getInstanceInitMethods(mclass)) {//TODO [IMPORTANT] loop here seems wrong
                                MyUtil.printlnOutput("--> Analyzing "+temp_method.getSignature(), MyConstant.DEBUG);
                                
                                vlm.setCurrentMethod(temp_method);
                                boolean isTainted = MethodWorker.v().backwardUnit(null, temp_method, track, index);
                                //
                                // avoid the buggy loop in hu.tagsoft.ttorrent.webserver.a.j <init>(int)
                                // Then correct:
                                // --> Analyzing <hu.tagsoft.ttorrent.webserver.a.j: void <init>(int)>
                                // --> Analyzing <hu.tagsoft.ttorrent.webserver.a.j: void <init>(int,byte)>
                                //
                                if (isTainted) {
                                    furtherCheck(track);    //TODO put inside the loop?
                                    break;  //no longer check other init methods. Reply to the TODO above
                                }
                                else {
                                    continue;
                                }
                            }
                        }
                        else {
                            MyUtil.printlnOutput(String.format("--> %s is a parameter field", base),
                                    MyConstant.DEBUG);
                            
                            //TODO do alias analysis
                        }
                    }
                    else {
                        MyUtil.printlnOutput(String.format("--> %s is not a local type (this or parameter)", base),
                                MyConstant.RELEASE);
                    }
                }
                /*
                 * 3) Static field
                 */
                else if (last_v instanceof StaticFieldRef) {
                    StaticFieldRef sfr = (StaticFieldRef)last_v;
                    SootField sf = sfr.getField();
                    SootClass sf_class = sf.getDeclaringClass();
                    MyUtil.printlnOutput(String.format("--> StaticFieldRef: %s, class: %s",
                            last_v, sf_class), MyConstant.DEBUG);
                    
                    SootMethod sf_clinit = getOneStaticInitMethod(sf_class);
                    if (sf_clinit != null) {
                        MyUtil.printlnOutput("--> Analyzing "+sf_clinit.getSignature(), MyConstant.DEBUG);
                        
                        vlm.setCurrentMethod(sf_clinit);
                        boolean isTainted = MethodWorker.v().backwardUnit(null, sf_clinit, track, index);
                        //
                        // avoid the buggy loop in <xcxin.filexpert.ftpserver.FTPServerService: void a()>
                        //
                        if (isTainted) {
                            furtherCheck(track);
                        }
                        else {
                            List<SootMethod> methods = sf_class.getMethods();
                            for (SootMethod m : methods) {
                                MyUtil.printlnOutput("--> Analyzing "+m.getSignature(), MyConstant.DEBUG);
                                
                                vlm.setCurrentMethod(m);
                                isTainted = MethodWorker.v().backwardUnit(null, m, track, index);
                                if (isTainted) {
                                    furtherCheck(track);
                                    break;
                                }
                            }
                        }
                    }
                    else {
                        // TODO
                    }
                }
                /*
                 * TODO
                 * 4) Return
                 * -- $i0 = staticinvoke <com.kugou.framework.e.b.b.a: int c()>();
                 * -- $i0 = virtualinvoke $r5.<hu.tagsoft.ttorrent.torrentservice.o: int K()>()
                 * -- $i1 = virtualinvoke r3.<xcxin.filexpert.settings.i: int J()>();
                 * -- virtualinvoke $r6.<org.teleal.cling.transport.impl.apache.StreamServerConfigurationImpl: int getListenPort()>()
                 * 
                 * If there are parameter in this return, we need to handle it carefully
                 * -- $i1 = staticinvoke <com.afollestad.neuron.Terminal: int access$000(com.afollestad.neuron.Terminal)>($r5);
                 */
                else if (last_v instanceof InvokeExpr) {
                    MyUtil.printlnOutput(String.format("--> Handling recorded InvokeExpr: %s", last_v),
                            MyConstant.DEBUG);
                    
                    Unit unit = UnitWorker.v().getOneUnit(last_v);
                    CallGraph cg = ClassWorker.getCallGraph();
                    
                    Iterator<Edge> edges = cg.edgesOutOf(unit);
                    while (edges.hasNext()) {
                        Edge edge = edges.next();
                        SootMethod tgt_method = edge.tgt();
                        String tgt_method_sig = tgt_method.getSignature();
                        MyUtil.printlnOutput("==> "+tgt_method_sig, MyConstant.DEBUG);
                        
                        //
                        // Filter non-app class
                        // e.g., java.util.AbstractMap$SimpleEntry
                        //
                        String tgt_classname = tgt_method.getDeclaringClass().getName();
                        if (PortDetector.apiClassSet.contains(tgt_classname))
                            continue;
                        
                        //
                        // Analyze return value
                        //
                        // TODO cannot handle well when it has parameters
                        // TODO should do forward analysis here, and insert parameters here
                        // TODO i.e., give a method summary
                        //
                        MyUtil.printlnOutput(String.format("--> Analyzing InvokeExpr Return: %s", tgt_method_sig),
                                MyConstant.DEBUG);
                        Body tgt_body = MyUtil.retrieveActiveSSABody(tgt_method);
                        PatchingChain<Unit> tgt_u_chain = tgt_body.getUnits();
                        Unit tgt_last_unit = tgt_u_chain.getLast();
                        
                        if (tgt_last_unit instanceof ReturnStmt) {
                            ReturnStmt tgt_rs = (ReturnStmt)tgt_last_unit;
                            Value tgt_rs_value = tgt_rs.getOp();
                            
                            pc.addTaintValue(index, tgt_rs_value, tgt_method); //no split here                         
                            boolean isTainted = MethodWorker.v().backwardUnit(tgt_last_unit, tgt_u_chain, track, index);
                            
                            if (isTainted) {
                                furtherCheck(track);
                                break;  //TODO only handle one flow???
                                
                            } else {
                                continue;
                            }
                        }
                        else {
                            MyUtil.printlnOutput(String.format("%s The last unit is not a return stmt", 
                                    MyConstant.CriticalPrefix), MyConstant.RELEASE);
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Did not handle other callbacks
     * 
     * @param mclass
     * @return
     */
    public static Set<CallerContainer> findThisStartCallers(SootClass mclass) {
        Set<CallerContainer> caller_methods = new HashSet<CallerContainer>();
        
        if (mclass == null)
            return caller_methods;
        
        Iterator<SootMethod> method_iter = mclass.methodIterator();
        
        while (method_iter.hasNext()) {
            SootMethod method = method_iter.next();
            
            Body body = MyUtil.retrieveActiveSSABody(method);
            if (body == null)
                continue;
            
            Iterator<Unit> iter_u = body.getUnits().iterator();
            boolean isThisInit = false;
            while (iter_u.hasNext()) {
                Unit unit = iter_u.next();
                String unit_str = unit.toString();
                if (unit_str.contains("<java.lang.Thread: void <init>(java.lang.Runnable)>(r0)")) {
                    isThisInit = true;
                } else if (isThisInit &&
                        unit_str.contains("<java.lang.Thread: void start()>()")) {
                    MyUtil.printlnOutput(String.format("%s findThisStartCallers %s at %s",
                            MyConstant.BackPrefix, unit, method.getSignature()),
                            MyConstant.WARN);
                    CallerContainer cc = new CallerContainer(unit, method);
                    caller_methods.add(cc);
                    return caller_methods;  //TODO currently we only find one
                }
            }
        }
        
        return caller_methods;
    }
    
    
    /**
     * Get a list of instance init methods from a SootClass
     * 
     * @param mclass
     * @return
     */
    public static List<SootMethod> getInstanceInitMethods(SootClass mclass) {
        if (mclass == null)
            return null;
        
        List<SootMethod> results = new ArrayList<SootMethod>();
        
        Iterator<SootMethod> method_iter = mclass.methodIterator();
        while (method_iter.hasNext()) {
            SootMethod method = method_iter.next();
            
            if (method.getName().equals("<init>"))
                results.add(method);
        }
        
        return results;
    }
    
    /**
     * Get one static clinit method from a SootClass
     * 
     * @param mclass
     * @return
     */
    public static SootMethod getOneStaticInitMethod(SootClass mclass) {
        if (mclass == null)
            return null;
        
        SootMethod result = null;
        
        Iterator<SootMethod> method_iter = mclass.methodIterator();
        while (method_iter.hasNext()) {
            SootMethod method = method_iter.next();
            
            if (method.getName().equals("<clinit>")) {
                result = method;
                break;
            }
        }
        
        return result;
    }
    
    /**
     * TODO spark points-to analysis is required
     * 
     * @return
     */
    public static CallGraph getCallGraph() {
        /*
         * Use DumbPointerAnalysis, a naive pointer analysis, to generate call graph
         * TODO More precise way is needed.
         * 
         * https://soot-build.cs.uni-paderborn.de/doc/soot/soot/jimple/toolkits/callgraph/CallGraphBuilder.html
         * https://soot-build.cs.uni-paderborn.de/doc/soot/soot/PointsToAnalysis.html
         * https://soot-build.cs.uni-paderborn.de/doc/soot/soot/jimple/spark/pag/PAG.html
         * https://soot-build.cs.uni-paderborn.de/doc/soot/soot/options/SparkOptions.html
         * https://soot-build.cs.uni-paderborn.de/doc/soot/soot/Context.html
         */
        CallGraphBuilder cgbuilder = new CallGraphBuilder();
        cgbuilder.build();
        CallGraph cg = Scene.v().getCallGraph();
        return cg;
    }

}
