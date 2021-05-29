package edu.smu.backdroid.util;

import com.google.common.base.Throwables;

import edu.smu.backdroid.PortDetector;
import edu.smu.backdroid.analysis.ClassWorker;
import edu.smu.backdroid.analysis.ManifestWorker;
import edu.smu.backdroid.graph.BDGEdge;
import edu.smu.backdroid.graph.BDGEdgeType;
import soot.Body;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.DefinitionStmt;
import soot.jimple.GotoStmt;
import soot.jimple.IfStmt;
import soot.jimple.InterfaceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.LookupSwitchStmt;
import soot.jimple.ReturnStmt;
import soot.jimple.SpecialInvokeExpr;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.TableSwitchStmt;
import soot.jimple.VirtualInvokeExpr;
import soot.shimple.Shimple;
import soot.util.Chain;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MyUtil {
    
    public static int uniqueCmdNum = 0;
    
    public static int cachedCmdNum = 0;
    
    public static Map<String, String> childClsMap = new HashMap<String, String>();
    
    public static Map<String, List<String>> cmdResCache = new HashMap<String, List<String>>();
    
    public static Map<String, String> rootClsMap = new HashMap<String, String>();
    
    public static Map<String, Boolean> staticInitCache = new HashMap<String, Boolean>();
    
    /**
     * grep DexDumpLog to obtain a set of class names
     * 
     * The grep output is like as follows:
     * Lcom/kugou/android/dlna/d/b/a;
       Lcom/kugou/android/mediatransfer/pctransfer/socket/a;
       Lcom/kugou/framework/e/b/a/s;
       Lcom/kugou/framework/e/c/a/b;
     * 
     * And we need to replace it to obtain "com.kugou.android.dlna.d.b.a"
     * 
     * @param cmdcontent
     * @return
     */
    public static List<String> grepDexDumpLogForClass(String cmdcontent) {
        List<String> results = new ArrayList<String>();
        
        // http://stackoverflow.com/a/5928316/197165
        String[] cmd = {
                    "/bin/sh",
                    "-c",
                    cmdcontent
                    };
        
        try {
            // http://stackoverflow.com/a/5711150/197165
            Process proc = Runtime.getRuntime().exec(cmd);
            BufferedReader stdInput = new BufferedReader(
                    new InputStreamReader(proc.getInputStream()));
            String s = null;
            while ((s = stdInput.readLine()) != null) {
                //
                // fix bug: split("L")[1] --> substring(1)
                //
                s = s.substring(1).split(";")[0].replace("/", ".");
                results.add(s);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        return results;
    }
    
    public static List<String> grepCmdResult(String cmdcontent, boolean isCache) {
        // Check the cache
        if (cmdResCache.containsKey(cmdcontent)) {
            cachedCmdNum++;
            return cmdResCache.get(cmdcontent);
        }
        
        // No cache
        List<String> results = new ArrayList<String>();
        
        // http://stackoverflow.com/a/5928316/197165
        String[] cmd = {
                    "/bin/sh",
                    "-c",
                    cmdcontent
                    };
        
        try {
            // http://stackoverflow.com/a/5711150/197165
            Process proc = Runtime.getRuntime().exec(cmd);
            BufferedReader stdInput = new BufferedReader(
                    new InputStreamReader(proc.getInputStream()));
            String s = null;
            while ((s = stdInput.readLine()) != null) {
                results.add(s);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // Add the current result to cache
        if (isCache) {
            uniqueCmdNum++;
            cmdResCache.put(cmdcontent, results);
        }
        
        return results;
    }
    
    /**
     * Handle the following two sentences:
     *     #0              : (in Lcom/lge/app1/fragement/SettingFragment$8;)
     *     2051b0:                                        |[2051b0] com.lge.app1.fragement.SettingFragment.8.onClick:(Landroid/view/View;)V
     *     
     * @param cmdcontent
     * @return methods in dexdump format TODO return list or set?
     */
    public static List<String> grepMethodResult(String cmdcontent) {
        // Check the cache
        if (cmdResCache.containsKey(cmdcontent)) {
            cachedCmdNum++;
            return cmdResCache.get(cmdcontent);
        }
        
        // No cache
        List<String> results = new ArrayList<String>();
        
        // http://stackoverflow.com/a/5928316/197165
        String[] cmd = {
                    "/bin/sh",
                    "-c",
                    cmdcontent
                    };
        
        try {
            // http://stackoverflow.com/a/5711150/197165
            Process proc = Runtime.getRuntime().exec(cmd);
            BufferedReader stdInput = new BufferedReader(
                    new InputStreamReader(proc.getInputStream()));
            String s = null;
            String pre_s = "";
            String one_method;
            while ((s = stdInput.readLine()) != null) {
                if (s.contains(" : (in ")) {
                    // "Lcom/lge/app1/fragement/SettingFragment$8;"
                    pre_s = s.split(" : \\(in ")[1].replace(")", "");
                    // "com.lge.app1.fragement.SettingFragment$8"
                    pre_s = transformIntoSootValueType(pre_s);
                } else {
                    if (pre_s.equals("")) {
                        // To fix StringIndexOutOfBoundsException in com.wecut.vapor
                        MyUtil.printlnOutput(String.format("%s A strange grepMethodResult: %s",
                                MyConstant.ErrorPrefix, s), MyConstant.RELEASE);
                        continue;
                    }
                    // "com.lge.app1.fragement.SettingFragment.8.onClick:(Landroid/view/View;)V"
                    one_method = s.split("] ")[1];
                    int begInx = pre_s.length();
                    one_method = pre_s + one_method.substring(begInx);
                    results.add(one_method);
                    // reset
                    pre_s = "";
                }
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // Add the current result to cache
        uniqueCmdNum++;
        cmdResCache.put(cmdcontent, results);
        
        return results;
    }
    
    /**
     * grep DexDumpLog to obtain a set of method names
     * 
     * The grep output is like as follows:
     * ] xcxin.filexpert.ftpserver.FTPServerService.a:(Landroid/content/Intent;)Z
     * ] xcxin.filexpert.ftpserver.FTPServerService.a:()V
     * 
     * And we need to replace it to obtain "<xcxin.filexpert.ftpserver.FTPServerService: void a()>"
     * 
     * Could be deprecated and replaced by grepMethodResult()
     * 
     * @param cmdcontent
     * @return
     * @deprecated
     */
    public static Set<String> grepDexDumpLogForMethod(String cmdcontent) {
        Set<String> results = new HashSet<String>();
        
        // http://stackoverflow.com/a/5928316/197165
        String[] cmd = {
                    "/bin/sh",
                    "-c",
                    cmdcontent
                    };
        
        try {
            // http://stackoverflow.com/a/5711150/197165
            Process proc = Runtime.getRuntime().exec(cmd);
            BufferedReader stdInput = new BufferedReader(
                    new InputStreamReader(proc.getInputStream()));
            String s = null;
            while ((s = stdInput.readLine()) != null) {
                //
                // 1st: "] xcxin.filexpert.ftpserver.FTPServerService.a:()V"
                // 2nd: "xcxin.filexpert.ftpserver.FTPServerService.a:()V"
                // 3rd: "<xcxin.filexpert.ftpserver.FTPServerService: void a()>"
                //
                s = s.substring(2);//2nd
                
                s = transformIntoSootMSig(s);//3rd
                
                MyUtil.printlnOutput(String.format("%s grepDexDumpLogForMethod: %s",
                        MyConstant.NormalPrefix, s), MyConstant.DEBUG);
                
                results.add(s);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        return results;
    }
    
    /**
     * Cache has been done by grepCmdResult()
     * 
     * @param dexdump_clsname
     * @return Also in the dexdump format
     */
    public static List<String> searchChildClass(String dexdump_clsname) {
        String cmdcontent = String.format("cat %s " +
                "| grep -B 3 -e \"Superclass        : '%s'\" " +
                "| grep \"Class descriptor\" " +
                "| grep -o \"L.*;\"", PortDetector.DEXDUMPlog,
                sanitizeSS(dexdump_clsname));
        MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                MyConstant.NormalPrefix, cmdcontent), MyConstant.DEBUG);
        
        List<String> child_classes = MyUtil.grepCmdResult(cmdcontent, true);
        MyUtil.printlnOutput(String.format("%s find child classes: %s",
                MyConstant.NormalPrefix, child_classes), MyConstant.DEBUG);
        
        return child_classes;
    }
    
    public static List<String> searchInvokedClass(String cls_search) {
        String cmdcontent = String.format("cat %s " +
                "| grep -e \", %s\" -e \"Class descriptor\" " +
                "| grep -B 1 -e \", %s\" " +
                "| grep \"Class descriptor\" " +
                "| grep -o \"L.*;\"", PortDetector.DEXDUMPlog,
                sanitizeSS(cls_search), sanitizeSS(cls_search));
        MyUtil.printlnOutput(String.format("%s cls_search grep cmd: %s",
                MyConstant.NormalPrefix, cmdcontent), MyConstant.DEBUG);
        
        List<String> invoked_classes = MyUtil.grepCmdResult(cmdcontent, false);
        return invoked_classes;
    }
    
    public static List<String> searchContainedClass(String cls_search) {
        String cmdcontent = String.format("cat %s " +
                "| grep -e \"%s\" -e \"Class descriptor\" " +
                "| grep -B 1 -e \"%s\" " +
                "| grep \"Class descriptor\" " +
                "| grep -o \"L.*;\"", PortDetector.DEXDUMPlog,
                sanitizeSS(cls_search), sanitizeSS(cls_search));
        MyUtil.printlnOutput(String.format("%s cls_search grep cmd: %s",
                MyConstant.NormalPrefix, cmdcontent), MyConstant.DEBUG);
        
        List<String> invoked_classes = MyUtil.grepCmdResult(cmdcontent, false);
        return invoked_classes;
    }
    
    
    /**
     * Determine whether a static initializer will be triggered or not
     * 
     * @param cls_name_soot
     * @return false if not reachable
     */
    public static boolean judgeStaticInitializer(String cls_name_soot) {
        if (staticInitCache.containsKey(cls_name_soot))
            return staticInitCache.get(cls_name_soot).booleanValue();
        
        MyUtil.printlnOutput(String.format("%s Analyze static initializer: %s",
                MyConstant.ForwardPrefix, cls_name_soot), MyConstant.DEBUG);
        Set<String> maniCompSet = ManifestWorker.v().getManiCompSet();
        
        // First check direct class
        String cls_name_dex = transformIntoDexDumpValueType(cls_name_soot);
        List<String> first_clses_dex = searchContainedClass(cls_name_dex);
        for (String first_cls_dex : first_clses_dex) {
            String first_cls_soot = transformIntoSootValueType(first_cls_dex);
            if (maniCompSet.contains(first_cls_soot)) {
                MyUtil.printlnOutput(String.format("[StaticInit]%s---%s---%s",
                        PortDetector.PKGmust, cls_name_soot, first_cls_soot), MyConstant.RELEASE);
                staticInitCache.put(cls_name_soot, new Boolean(true));
                return true;
            }
        }
        
        // Second round
        Set<String> second_clses_dex = new HashSet<String>();
        for (String first_cls_dex : first_clses_dex) {
            List<String> contained_clses_dex = searchContainedClass(first_cls_dex);
            for (String contained_cls_dex : contained_clses_dex) {
                String contained_cls_soot = transformIntoSootValueType(contained_cls_dex);
                if (maniCompSet.contains(contained_cls_soot)) {
                    MyUtil.printlnOutput(String.format("[StaticInit]%s---%s---%s",
                            PortDetector.PKGmust, cls_name_soot, contained_cls_soot), MyConstant.RELEASE);
                    staticInitCache.put(cls_name_soot, new Boolean(true));
                    return true;
                }
                second_clses_dex.add(contained_cls_dex);
            }
        }
        
        // TODO currently do only third round
        for (String second_cls_dex : second_clses_dex) {
            List<String> contained_clses_dex = searchContainedClass(second_cls_dex);
            for (String contained_cls_dex : contained_clses_dex) {
                String contained_cls_soot = transformIntoSootValueType(contained_cls_dex);
                if (maniCompSet.contains(contained_cls_soot)) {
                    MyUtil.printlnOutput(String.format("[StaticInit]%s---%s---%s",
                            PortDetector.PKGmust, cls_name_soot, contained_cls_soot), MyConstant.RELEASE);
                    staticInitCache.put(cls_name_soot, new Boolean(true));
                    return true;
                }
            }
        }
        
        MyUtil.printlnOutput(String.format("[StaticInit]%s---%s---NotReachable",
                PortDetector.PKGmust, cls_name_soot), MyConstant.RELEASE);
        staticInitCache.put(cls_name_soot, new Boolean(false));
        return false;
    }
    
    /**
     * 
     * @param raw_cls_name "com.lge.app1.service.TVConnectionService$1"
     * @return The DexDump format of 
     *  Lcom/lge/app1/service/TVConnectionService$1;
     *  Lcom/lge/app1/service/TVConnectionService;
     */
    public static List<String> searchMtdAppearClasses(String raw_cls_name) {
        // "Lcom/lge/app1/service/TVConnectionService$1;"
        String search_cls_name = transformIntoDexDumpValueType(raw_cls_name);
        // "Lcom/lge/app1/service/TVConnectionService\$1;"
        search_cls_name = sanitizeSS(search_cls_name);
        
        String cmdcontent = String.format("cat %s " +
                "| grep -e \", %s\" -e \"Class descriptor\" " +
                "| grep -B 1 -e \", %s\"" +
                "| grep -e \"Class descriptor\" | grep -o \"L.*;\"",
                PortDetector.DEXDUMPlog, search_cls_name, search_cls_name);
        MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                MyConstant.NormalPrefix, cmdcontent), MyConstant.DEBUG);
        
        return MyUtil.grepCmdResult(cmdcontent, true);
    }
    
    public static List<String> transformToJavaFormat(List<String> old_list_str) {
        List<String> new_list_str = new ArrayList<String>();
        
        for (String old_str : old_list_str) {
            String new_str = transformIntoSootValueType(old_str);
            new_list_str.add(new_str);
        }
        
        return new_list_str;
    }
    
    public static boolean containsListElement(String target_str, List<String> list_str) {
        boolean result = false;
        
        for (String one_str : list_str) {
            if (target_str.contains(one_str)) {
                result = true;
                break;
            }
        }
        
        return result;
    }
    
    /**
     * Sanitize string for search
     * 
     * @param oldstr
     * @return
     */
    public static String sanitizeSS(String oldstr) {
        return oldstr.replace("$", "\\$").replace("[", "\\[");
    }
    
    /**
     * Similar to transformIntoSearchMethod()
     * If cannot find, simply return the old method
     * 
     * TODO Ideally, shall return a list of SootMethod
     * TODO Currently, we simply return the first method, which causes the first child class being returned
     * 
     * TODO cache...
     * 
     * @param old_expr:
     *      virtualinvoke r0.<org.apache.commons.vfs2.FileSystemConfigBuilder: java.lang.Class getConfigClass()>()
     *      interfaceinvoke r1.<org.apache.commons.vfs2.UserAuthenticator: org.apache.commons.vfs2.UserAuthenticationData requestAuthentication(org.apache.commons.vfs2.UserAuthenticationData$Type[])>(r0)
     * @return
     */
    public static SootMethod findRealMethod(InvokeExpr old_expr) {
        SootMethod old_mtd = old_expr.getMethod();
        
        /*
         * simplify for some InvokeExpr
         * TODO more kinds?
         * https://www.sable.mcgill.ca/soot/doc/soot/jimple/InstanceInvokeExpr.html
         */
        if (old_expr instanceof StaticInvokeExpr
                || old_expr instanceof SpecialInvokeExpr) {
            return old_mtd;
        }
        
        String old_cls_name = old_mtd.getDeclaringClass().getName();
        String old_dexdump_cls_name = transformIntoDexDumpValueType(old_cls_name);
        String mtd_subsig = old_mtd.getSubSignature();
        
        String new_cls_name;
        SootClass new_cls;
        SootMethod new_mtd;
        String cmdcontent;
        
        /*
         * Handle interface method
         * TODO interface hierarchy
         * TODO why -B 10
         */
        if (old_expr instanceof InterfaceInvokeExpr) {
            cmdcontent = String.format("cat %s " +
                    "| grep -B 10 -e \"    #.* : '%s'\" " +
                    "| grep \"Class descriptor\" " +
                    "| grep -o \"L.*;\"", PortDetector.DEXDUMPlog,
                    sanitizeSS(old_dexdump_cls_name));
            MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                    MyConstant.NormalPrefix, cmdcontent), MyConstant.DEBUG);
            
            List<String> classes = MyUtil.grepCmdResult(cmdcontent, true);
            for (String tempclass : classes) {
                // "Lorg/apache/commons/vfs2/auth/StaticUserAuthenticator;"
                MyUtil.printlnOutput(String.format("%s find the class implementing interface: %s",
                        MyConstant.NormalPrefix, tempclass), MyConstant.DEBUG);
                
                new_cls_name = transformIntoSootValueType(tempclass);
                new_cls = ClassWorker.loadClass(new_cls_name);
                
                // Further analyze child class
                if (new_cls.isAbstract()) {
                    List<String> child_classes = searchChildClass(tempclass);
                    for (String child_tempclass : child_classes) {
                        new_cls_name = transformIntoSootValueType(child_tempclass);
                        new_cls = ClassWorker.loadClass(new_cls_name);
                        
                        try {
                            new_mtd = new_cls.getMethod(mtd_subsig);
                            return new_mtd;
                        } catch(RuntimeException e) {
                            // method does not exist in the class
                        }
                    }
                    continue;
                }
                
                try {
                    new_mtd = new_cls.getMethod(mtd_subsig);
                    return new_mtd;
                } catch(RuntimeException e) {
                    // method does not exist in the class
                }
            }
        }
        /*
         * Handle instance methods
         */
        else if (old_expr instanceof VirtualInvokeExpr) {
            /*
             * Simplified handling for *this* call
             */
            if (old_expr.toString().startsWith("virtualinvoke r0")) {
                if (old_mtd.isConcrete())   //TODO is this check correct?
                    return old_mtd;
                else                        //TODO does such case exist?
                    MyUtil.printlnOutput(String.format("%s virtualinvoke r0 does not have: %s",
                            MyConstant.ErrorPrefix, old_expr),
                            MyConstant.WARN);
            }
            
            /*
             * Otherwise, keep the following logic
             */
            List<String> classes = searchChildClass(old_dexdump_cls_name);
            for (String tempclass : classes) {
                new_cls_name = transformIntoSootValueType(tempclass);
                new_cls = ClassWorker.loadClass(new_cls_name);
                
                // Further analyze child class
                if (new_cls.isAbstract()) {
                    List<String> child_classes = searchChildClass(tempclass);
                    for (String child_tempclass : child_classes) {
                        new_cls_name = transformIntoSootValueType(child_tempclass);
                        new_cls = ClassWorker.loadClass(new_cls_name);
                        
                        try {
                            new_mtd = new_cls.getMethod(mtd_subsig);
                            return new_mtd;
                        } catch(RuntimeException e) {
                            // method does not exist in the class
                        }
                    }
                    continue;
                }
                
                try {
                    new_mtd = new_cls.getMethod(mtd_subsig);
                    return new_mtd;
                } catch(RuntimeException e) {
                    // method does not exist in the class
                }
            }
        }
        /*
         * TODO Other invokes?
         */
        else {
            MyUtil.printlnOutput(String.format("%s Detect an unrecognized invoke: %s",
                    MyConstant.ErrorPrefix, old_expr),
                    MyConstant.WARN);
        }
        
        return old_mtd;
    }
    
    /**
     * Take care of the class hierarchy
     * <com.studiosol.utillibrary.IO.NanoHTTPD: void start()>
     * ==>
     * <com.studiosol.utillibrary.IO.NanoHTTPD: void start()>
     * --> Lcom/studiosol/utillibrary/IO/NanoHTTPD;.start:()V
     * <com.studiosol.palcomp3.Backend.Cache.MP3LocalServer: void start()>
     * --> Lcom/studiosol/palcomp3/Backend/Cache/MP3LocalServer;.start:()V
     * 
     * TODO provide the doc for IPC and interface search
     * 
     * @param method
     * @return
     */
    public static Map<String, StringBuilder> transformIntoSearchMethod(
            final SootMethod method, final boolean isDirectSignature) {
        Map<String, StringBuilder> results = new LinkedHashMap<String, StringBuilder>();
        StringBuilder sb;
        List<String> key_list = new ArrayList<String>();// Save soot msig
        List<StringBuilder> value_list = new ArrayList<StringBuilder>();// Save dex search sig
        
        SootClass mclass = method.getDeclaringClass();
        String clsname_soot = mclass.getName();//com.kugou.android.dlna.d.b.a
        
        String msig = method.getSignature();
        String msubsig = method.getSubSignature();
        String methodname = method.getName();
        String paramname = null;
        String returnname = null;
        
        /**
         * @WriteIntoPaper
         * First determine which method can be directly searched
         * TODO if method is abstract?
         */
        boolean isSignatureMethod = false;
        // TODO final method like executeOnExecutor() does not apply
        if (method.isStatic() || method.isPrivate()
                || method.isConstructor()) {
            if (false) {
            /*
             * Special handling for static initializers
             * <com.heyzap.internal.FileFetchClient: void <clinit>()>
             */
            if (msubsig.equals("void <clinit>()")) {
                methodname = "<init>";
                msubsig = "void <init>()";
                msig = String.format("<%s: %s>", clsname_soot, msubsig);
            }
            }
            
            isSignatureMethod = true;
            MyUtil.printlnOutput(String.format("%s isSignatureMethod: %s",
                    MyConstant.NormalPrefix, msig),
                    MyConstant.DEBUG);
        }
        if (isDirectSignature) {
            // Here we are just interested in the raw signature search
            isSignatureMethod = true;
        }
        
        if (!isSignatureMethod) {
            /*
             * TODO Still keep the current way for IPC
             * 
             * Search over IPC
             * 
             * TODO analyze manifest to determine explicit/implicit Intent
             */
            if (msig.contains("int onStartCommand(android.content.Intent,int,int)")
                    || msig.contains("void onStart(android.content.Intent,int)")
                    || msig.contains("void onReceive(android.content.Context,android.content.Intent)")
                    || msig.contains("void onActivityResult(int,int,android.content.Intent)")) {
                /*
                 * More accurate determination, e.g., whether it is a Service class
                 * TODO not handle ContentProvider yet
                 */
                String rootclsname = getRootClsName(mclass);
                if (rootclsname.equals("android.support.v4.app.Fragment")
                        || rootclsname.equals("android.app.Fragment")
                        || rootclsname.equals("android.app.Activity")
                        || rootclsname.equals("android.app.Service")
                        || rootclsname.equals("android.content.BroadcastReceiver")
                        || rootclsname.equals("android.content.ContentProvider")) {
                    // The first search
                    String search_intent_class = String.format("const-class .*, %s",
                            MyUtil.transformIntoDexDumpValueType(clsname_soot));
                    sb = new StringBuilder();
                    sb.append(search_intent_class);
                    
                    //
                    // Service
                    //
                    if (msig.contains("int onStartCommand(android.content.Intent,int,int)")
                            || msig.contains("void onStart(android.content.Intent,int)")) {
                        results.put(MyConstant.startService_SubSig, sb);
                    }
                    //
                    // Receiver
                    // TODO sendBroadcast(Intent, String)  sendOrderedBroadcast(Intent, String)
                    //
                    else if (msig.contains("void onReceive(android.content.Context,android.content.Intent)")) {
                        results.put(MyConstant.sendBroadcast_SubSig, sb);
                    }
                    //
                    // Activity
                    // TODO startActivityForResult(android.content.Intent, int, android.os.Bundle)
                    //
                    else if (msig.contains("void onActivityResult(int,int,android.content.Intent)")) {
                        results.put(MyConstant.startActivityForResult_SubSig, sb);
                    }
                    
                    return results;
                }
            }
        }
        
        /**
         * calculate class name first
         */
        /*
         * *First* add the current class itself
         */
        sb = new StringBuilder();
        sb.append("L");
        sb.append(clsname_soot.replace(".", "/")); //replace "$" will be done outside
        sb.append(";");
        key_list.add(msig);
        value_list.add(sb);
        String clsname_dex = sb.toString();
        
        /*
         * Then add other class
         * 
         * TODO how about the parent class?
         */
        if (!isSignatureMethod) {
            // TODO Issue #70:
            // Check the class hierarchy
            // This is the best way
//            if (childClsMap.containsKey(newclsname))
            
            /*
             * Find child, and child child classes
             */
            List<String> classes = searchChildClass(clsname_dex);
            for (String childclsname_dex : classes) {
                // Only a child class does not contain the method, we then can search it
                String childclsname_soot = transformIntoSootValueType(childclsname_dex);
                SootClass childclass = ClassWorker.loadClass(childclsname_soot);
                if (!isMethodInClass(childclass, msubsig)) {
                    // "Lcom/studiosol/palcomp3/Backend/Cache/MP3LocalServer;"
                    MyUtil.printlnOutput(String.format("%s find child class: %s",
                            MyConstant.NormalPrefix, childclsname_dex), MyConstant.DEBUG);
                    sb = new StringBuilder();
                    sb.append(childclsname_dex);
                    key_list.add(msig.replaceFirst(Pattern.quote(clsname_soot), 
                                                Matcher.quoteReplacement(childclsname_soot)));
                    value_list.add(sb);
                }
                
                List<String> subclsnames_dex = searchChildClass(childclsname_dex);
                for (String subclsname_dex : subclsnames_dex) {
                    String subclsname_soot = transformIntoSootValueType(subclsname_dex);
                    SootClass subclass = ClassWorker.loadClass(subclsname_soot);
                    
                    if (!isMethodInClass(subclass, msubsig)) {
                        // "Lhu/tagsoft/ttorrent/webserver/b;"
                        MyUtil.printlnOutput(String.format("%s find childchild class: %s",
                                MyConstant.NormalPrefix, subclsname_dex), MyConstant.DEBUG);
                        sb = new StringBuilder();
                        sb.append(subclsname_dex);
                        String temp_subclass = transformIntoSootValueType(subclsname_dex);
                        key_list.add(msig.replaceFirst(Pattern.quote(clsname_soot),
                                                    Matcher.quoteReplacement(temp_subclass)));
                        value_list.add(sb);
                    }
                }
            }
            
            /*
             * Find super class
             * See issue #90
             * 
             * TODO class hierarchy... super's super class
             */
            if (mclass.hasSuperclass()) {
                SootClass supercls = mclass.getSuperclass();
                SootMethod supermtd = null;
                try {
                    supermtd = supercls.getMethod(msubsig);
                } catch (Exception e) {
                }
                
                // Parent must contain that method
                if (supermtd != null) {
                    String supermtdsig = supermtd.getSignature();
                    String superclsname = supercls.getName();
                    
                    /*
                     * No need to differentiate abstract method or not
                     */
                    // TODO Full class hierarchy
                    if (PortDetector.apiClassSet.contains(superclsname)) {
                        // TODO how about https://developer.android.com/reference/android/os/HandlerThread.html#run()
                        if (supermtdsig.contains("void run()")) {//TODO Or "<java.lang.Thread: void run()>"?
                            MyUtil.printlnOutput(String.format("%s replace super method: %s",
                                    MyConstant.NormalPrefix, supermtdsig), MyConstant.DEBUG);
                            // Replace the sig search
                            msig = msig.replace("void run()",
                                                "void start()");
                            methodname = "start";
                            paramname = "";
                            returnname = "V";
                            key_list.set(0, msig);
                            
                            // Add the 2nd this search
                            sb = new StringBuilder();
                            sb.append("Ljava/lang/Thread;");
                            key_list.add(MyConstant.Search_INAPP+msig.replaceFirst(Pattern.quote(clsname_soot),
                                                                                    "java.lang.Thread"));
                            value_list.add(sb);
                        }
                        // TODO what about the child class of Handler
                        // Issue #74: other kinds of sendMessage()
                        // Partially handled by https://bitbucket.org/zout/backdroid/commits/b6ea222
                        else if (supermtdsig.contains("void handleMessage(android.os.Message)")) {
                            MyUtil.printlnOutput(String.format("%s replace super method: %s",
                                    MyConstant.NormalPrefix, supermtdsig), MyConstant.DEBUG);
                            // Replace the sig search
                            msig = msig.replace("void handleMessage(android.os.Message)",
                                                "boolean sendMessage(android.os.Message)");
                            methodname = "sendMessage";
                            paramname = "Landroid/os/Message;";
                            returnname = "Z";
                            key_list.set(0, msig);
                            
                            // Add the 2nd this search
                            sb = new StringBuilder();
                            sb.append("Landroid/os/Handler;");
                            key_list.add(MyConstant.Search_INAPP+msig.replaceFirst(Pattern.quote(clsname_soot),
                                                                                "android.os.Handler"));
                            value_list.add(sb);
                        }
                        // TODO the order of execute()
                        else if (supermtdsig.contains("java.lang.Object doInBackground(java.lang.Object[])")) {
                            MyUtil.printlnOutput(String.format("%s replace super method: %s",
                                    MyConstant.NormalPrefix, supermtdsig), MyConstant.DEBUG);
                            // Replace the sig search
                            msig = msig.replace("java.lang.Object doInBackground(java.lang.Object[])",
                                                    "android.os.AsyncTask execute(java.lang.Object[])");
                            methodname = "execute";
                            paramname = "[Ljava/lang/Object;";
                            returnname = "Landroid/os/AsyncTask;";
                            key_list.set(0, msig);
                            
                            // Add the 2nd this search
                            sb = new StringBuilder();
                            sb.append("Landroid/os/AsyncTask;");
                            key_list.add(MyConstant.Search_INAPP+msig.replaceFirst(Pattern.quote(clsname_soot),
                                                                                "android.os.AsyncTask"));
                            value_list.add(sb);
                        }
                        // TODO the order of execute()
                        else if (supermtdsig.contains("void onPostExecute(java.lang.Object)")) {
                            MyUtil.printlnOutput(String.format("%s replace super method: %s",
                                    MyConstant.NormalPrefix, supermtdsig), MyConstant.DEBUG);
                            // Replace the sig search
                            msig = msig.replace("void onPostExecute(java.lang.Object)",
                                            "android.os.AsyncTask execute(java.lang.Object[])");//TODO see issue #68
                            methodname = "execute";
                            paramname = "[Ljava/lang/Object;";
                            returnname = "Landroid/os/AsyncTask;";
                            key_list.set(0, msig);
                            
                            // Add the 2nd this search
                            sb = new StringBuilder();
                            sb.append("Landroid/os/AsyncTask;");
                            key_list.add(MyConstant.Search_INAPP+msig.replaceFirst(Pattern.quote(clsname_soot),
                                                                                "android.os.AsyncTask"));
                            value_list.add(sb);
                        }
                        else {
                            MyUtil.printlnOutput(String.format("%s skip super method: %s",
                                    MyConstant.ErrorPrefix, supermtdsig), MyConstant.RELEASE);
                        }
                    }
                    // Abstract: "com.baidu.pcsuite.swiftp.server.DataSocketFactory"
                    // Normal:   <com.lge.app1.fragement.BaseFragment: void enableButtons()>
                    else {
                        MyUtil.printlnOutput(String.format("%s find super method: %s",
                                MyConstant.NormalPrefix, supermtdsig), MyConstant.DEBUG);
                        sb = new StringBuilder();
                        sb.append("L");
                        sb.append(superclsname.replace(".", "/")); //replace "$" will be done outside
                        sb.append(";");
                        key_list.add(MyConstant.Search_INAPP+msig.replaceFirst(Pattern.quote(clsname_soot),
                                Matcher.quoteReplacement(superclsname)));
                        value_list.add(sb);
                    }
                }
            }
            
            /*
             * Find interface
             */
            Chain<SootClass> minterfaces = mclass.getInterfaces();
            for (SootClass minterface : minterfaces) {
                SootMethod intermtd = null;
                try {
                    intermtd = minterface.getMethod(msubsig);
                } catch (Exception e) {
                }
                
                if (intermtd != null) {
                    String interclsname = minterface.getName();
                    String intermtdsig = intermtd.getSignature();
                    
                    //
                    // Issue #59
                    // TODO better way to handle the interface search
                    //
                    if (PortDetector.apiClassSet.contains(interclsname)) {
                        if (intermtdsig.equals("<java.lang.Runnable: void run()>")) {
                            MyUtil.printlnOutput(String.format("%s replace interface method: %s",
                                    MyConstant.NormalPrefix, intermtdsig), MyConstant.DEBUG);
                            // Replace the sig search
                            msig = msig.replace("void run()",
                                                "void start()");
                            methodname = "start";
                            paramname = "";
                            returnname = "V";
                            key_list.set(0, msig);
                            
                            // Add the 2nd this search
                            sb = new StringBuilder();
                            sb.append("Ljava/lang/Thread;");
                            key_list.add(MyConstant.Search_INAPP+msig.replaceFirst(Pattern.quote(clsname_soot),
                                                                                    "java.lang.Thread"));
                            value_list.add(sb);
                        }
                        else {
                            MyUtil.printlnOutput(String.format("%s find interface method: %s",
                                    MyConstant.NormalPrefix, intermtdsig), MyConstant.DEBUG);
                            sb = new StringBuilder();
                            sb.append("L");
                            sb.append(interclsname.replace(".", "/")); //replace "$" will be done outside
                            sb.append(";");
                            key_list.add(MyConstant.Search_INSYS+msig.replaceFirst(Pattern.quote(clsname_soot), 
                                    Matcher.quoteReplacement(interclsname)));
                            value_list.add(sb);
                        }
                        
                    } else {
                        MyUtil.printlnOutput(String.format("%s find interface method: %s",
                                MyConstant.NormalPrefix, intermtdsig), MyConstant.DEBUG);
                        sb = new StringBuilder();
                        sb.append("L");
                        sb.append(interclsname.replace(".", "/")); //replace "$" will be done outside
                        sb.append(";");
                        key_list.add(MyConstant.Search_INAPP+msig.replaceFirst(Pattern.quote(clsname_soot), 
                                Matcher.quoteReplacement(interclsname)));
                        value_list.add(sb);
                    }
                }
            }
        }
        
        /**
         * calculate sub-signature then
         */
        sb = new StringBuilder();
        // method
        sb.append(".");
        sb.append(methodname);
        
        // parameters
        sb.append(":(");
        if (paramname == null) {
            List<Type> paras = method.getParameterTypes();
            for (Type para : paras) {
                sb.append(transformIntoDexDumpValueType(para.toString()));
            }
        } else {
            sb.append(paramname);
        }
        sb.append(")");
        
        // return values
        if (returnname == null) {
            Type returntype = method.getReturnType();
            sb.append(transformIntoDexDumpValueType(returntype.toString()));
        } else {
            sb.append(returnname);
        }
        
        String subsignature = sb.toString();
        
        /**
         * combine class name and sub-signature
         * Merge key_list and value_list into results
         */
        for (int i = 0; i < key_list.size(); i++) {
            String key = key_list.get(i);
            StringBuilder onesb = value_list.get(i);
            onesb.append(subsignature);
            results.put(key, onesb);
        }
        
        return results;
    }
    
    /**
     * Transform a SootMethod name into the dexdump format
     * 
     * <com.kugou.android.dlna.d.b.a: void <init>(int)>
     * ==>
     * Lcom/kugou/android/dlna/d/b/a;.<init>:(I)V
     * 
     * 
     * TODO run() --> start()
     * 
     * 
     * if not <init> method, then do not include class name
     * Because it may be an Interface method
     * (see com.samremote.view-16, org.teleal.cling.transport.impl.apache.StreamServerImpl)
     * 
     * 
     * Take care of the class hierarchy
     * <com.studiosol.utillibrary.IO.NanoHTTPD: void start()>
     * ==>
     * Lcom/studiosol/utillibrary/IO/NanoHTTPD;.start:()V
     * Lcom/studiosol/palcomp3/Backend/Cache/MP3LocalServer;.start:()V
     * 
     * @param name
     * @return
     * @deprecated
     */
    public static List<StringBuilder> transformIntoDexDumpMethod(SootMethod method) {
        List<StringBuilder> results = new ArrayList<StringBuilder>();
        StringBuilder sb;
        SootClass mclass = method.getDeclaringClass();
        String classname;
        
        /*
         * calculate class name first
         */
        // add itself
        sb = new StringBuilder();
        sb.append("L");
        classname = mclass.getName();//com.kugou.android.dlna.d.b.a
        sb.append(classname.replace(".", "/"));
        sb.append(";");
        String dexdump_clsname = sb.toString();
        results.add(sb);
        
        String methodname = method.getName();
        // TODO Sometimes the parameters later are not correct
//        if (methodname.equals("run"))  //TODO We need a systematic way
//            methodname = "start";
        
        // 
        // TODO how about the interface and parent class?
        // Comment this can indeed analyze more for xcxin.filexpert-258.apk, also much fast.
        //
        if (!methodname.equals("<init>")) {
            // TODO check the class hierarchy
//            if (childClsMap.containsKey(newclsname))
            
            // Search code text for child class
            // TODO to be a dedicated function
            // TODO handle multiple results
            String cmdcontent = String.format("cat %s " +
                    "| grep -B 3 -e \"Superclass        : '%s'\" " +
                    "| grep \"Class descriptor\" " +
                    "| grep -o \"L.*;\"", PortDetector.DEXDUMPlog,
                    sanitizeSS(dexdump_clsname));
            MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                    MyConstant.NormalPrefix, cmdcontent), MyConstant.DEBUG);
            
            List<String> classes = MyUtil.grepCmdResult(cmdcontent, true);
            for (String tempclass : classes) {
                // Lcom/studiosol/palcomp3/Backend/Cache/MP3LocalServer;
                MyUtil.printlnOutput("    return child class: "+tempclass, MyConstant.DEBUG);
                sb = new StringBuilder();
                sb.append(tempclass);
                results.add(sb);
            }
            
//            // add interfaces
//            Chain<SootClass> minterfaces = mclass.getInterfaces();
//            for (SootClass minterface : minterfaces) {
//                sb = new StringBuilder();
//                sb.append("L");
//                classname = minterface.getName();
//                sb.append(classname.replace(".", "/").replace("$", "\\$"));
//                sb.append(";");
//                results.add(sb);
//            }
//            
//            // add super class
//            if (mclass.hasSuperclass()) {
//                SootClass superclass = mclass.getSuperclass();
//                sb = new StringBuilder();
//                sb.append("L");
//                classname = superclass.getName();
//                sb.append(classname.replace(".", "/").replace("$", "\\$"));
//                sb.append(";");
//                results.add(sb);
//            }
        }
        
        /*
         * calculate sub-signature first
         */
        sb = new StringBuilder();
        // method
        sb.append(".");
        sb.append(methodname);
        
        // parameters
        sb.append(":(");
        List<Type> paras = method.getParameterTypes();
        for (Type para : paras) {
            sb.append(transformIntoDexDumpValueType(para.toString()));
        }
        sb.append(")");
        
        // return values
        Type returntype = method.getReturnType();
        sb.append(transformIntoDexDumpValueType(returntype.toString()));
        
        String subsignature = sb.toString();
        
        /*
         * combine class name and sub-signature
         */
        for (StringBuilder onesb : results) {
            onesb.append(subsignature);
        }
        
        return results;
    }
    
    /**
     * "<xcxin.filexpert.ftpserver.FTPServerService: int h>"
     * -->
     * "Lxcxin/filexpert/ftpserver/FTPServerService;.h:I"
     * 
     * @param oldfield
     * @return
     */
    public static String transformIntoDexDumpField(String oldfield) {
        StringBuilder sb = new StringBuilder();
        
        /*
         * Analyze the old field format
         */
        String[] oldsplits = oldfield.split(": ");
        // "xcxin.filexpert.ftpserver.FTPServerService"
        String oldclass = oldsplits[0].substring(1);
        // "int h"
        String oldsecond = oldsplits[1].substring(0, oldsplits[1].length()-1);
        String[] secondsplits = oldsecond.split(" ");
        String oldtype = secondsplits[0];
        String oldname = secondsplits[1];
        
        // class name
        sb.append("L");
        sb.append(oldclass.replace(".", "/"));
        sb.append(";");
        
        // field name
        sb.append(".");
        sb.append(oldname);
        
        // type name
        sb.append(":");
        sb.append(transformIntoDexDumpValueType(oldtype));
        
        return sb.toString();
    }
    
    /**
     * TODO more type transformation?
     * 
     * void     --> V
     * int      --> I
     * boolean  --> Z
     * long     --> J
     * byte     --> B
     * byte[]   --> [B
     * java.lang.Thread --> Ljava/lang/Thread;
     * 
     * One-word class:
     * jnamed   --> Ljnamed;
     * 
     * Lcom/lge/app1/media/NanoHTTPD$ServerRunnable;
     * $ is not replaced with "\$"
     * 
     * @param oldvalue
     * @return
     */
    public static String transformIntoDexDumpValueType(String value) {
        StringBuilder sb = new StringBuilder();
        
        // Array
        if (value.contains("[]")) {
            sb.append("[");
            value = value.replace("[]", "");
            sb.append(transformIntoDexDumpValueType(value)); //recursive
        }
        // class
        else if (value.contains(".")) {
            sb.append("L");
            sb.append(value.replace(".", "/"));
            sb.append(";");
        }
        else if (value.equals("void")) {
            sb.append("V");
        }
        else if (value.equals("int")) {
            sb.append("I");
        }
        else if (value.equals("boolean")) {
            sb.append("Z");
        }
        else if (value.equals("long")) {
            sb.append("J");
        }
        else if (value.equals("byte")) {
            sb.append("B");
        }
        else if (value.equals("float")) {
            sb.append("F");
        }
        else if (value.equals("double")) {
            sb.append("D");
        }
        else if (value.equals("short")) {
            sb.append("S");
        }
        else if (value.equals("char")) {
            sb.append("C");
        }
        // TODO
        else {
            MyUtil.printlnOutput(String.format("%s Should be one-word class: %s",
                    MyConstant.ErrorPrefix, value),
                    MyConstant.RELEASE);
            sb.append("L");
            sb.append(value);
            sb.append(";");
        }
        
        return sb.toString();
    }
    
    /**
     * xcxin.filexpert.ftpserver.FTPServerService.a:()V
     * -->
     * <xcxin.filexpert.ftpserver.FTPServerService: void a()>
     * 
     * xcxin.filexpert.ftpserver.FTPServerService.a:(Landroid/content/Intent;)Z
     * -->
     * <xcxin.filexpert.ftpserver.FTPServerService: boolean a(android.content.Intent)>
     * 
     * xcxin.filexpert.ftpserver.FTPServerService.onStart:(Landroid/content/Intent;I)V
     * -->
     * <xcxin.filexpert.ftpserver.FTPServerService: void onStart(android.content.Intent,int)>
     * 
     * com.studiosol.palcomp3.Backend.Cache.SmartCacheMgr.initLocalServer:(Landroid/content/Context;)V
     * -->
     * <com.studiosol.palcomp3.Backend.Cache.SmartCacheMgr: void initLocalServer(android.content.Context)>
     * 
     * @param oldmsig
     * @return
     */
    public static String transformIntoSootMSig(String oldmsig) {
        StringBuilder sb = new StringBuilder();
        sb.append("<");
        
        /*
         * analyze old msig
         */
        String[] oldsplits = oldmsig.split(":\\(");
        String firstsplit = oldsplits[0];   //xcxin.filexpert.ftpserver.FTPServerService.onStart
        int lastindex = firstsplit.lastIndexOf(".");
        String oldclass = firstsplit.substring(0, lastindex);
        String oldmethod = firstsplit.substring(lastindex+1);
        String secondsplit = oldsplits[1];  //"Landroid/content/Intent;I)V" or ")V"
        String[] secondsplits = secondsplit.split("\\)");
        String oldparams, oldreturn;
        if (secondsplits.length == 1) {     //")V"
            oldparams = "";
            oldreturn = secondsplits[0];
        }
        else {
            oldparams = secondsplits[0];
            oldreturn = secondsplits[1];
        }
        
        /*
         * class name
         * "xcxin.filexpert.ftpserver.FTPServerService: " 
         */
        sb.append(oldclass);
        sb.append(": ");
        
        /*
         * return value
         * "void " 
         */
        sb.append(transformIntoSootValueType(oldreturn));
        sb.append(" ");
        
        /*
         * method name
         * "onStart("
         */
        sb.append(oldmethod);
        sb.append("(");
        
        /*
         * Need to first split each parameter
         * Then we can call transformIntoSootValueType()
         * 
         * "android.content.Intent,int"
         * The difficult part
         * TODO any more type?
         */
        boolean hasPreParam = false;
        int paramlen = oldparams.length();
        for (int index = 0; index < paramlen; ) {
            char param = oldparams.charAt(index);
            // class
            if (param == 'L') {
                int nextindex = oldparams.indexOf(";", index);
                String oneparam = oldparams.substring(index, nextindex+1);
                if (hasPreParam)
                    sb.append(",");
                sb.append(transformIntoSootValueType(oneparam));
                hasPreParam = true;
                index = nextindex + 1; 
            }
            // array. Also handle: [[Ljava/lang/String;
            else if (param == '[') {
                // Similar processing in transformIntoSootValueType()
                int i;
                for (i = 1; i < 100; i++) {
                    char temp = oldparams.charAt(index+i);
                    if (temp != '[')
                        break;
                }
                // Determine whether with class
                int nextindex;
                char nextparam = oldparams.charAt(index+i);
                if (nextparam == 'L')
                    nextindex = oldparams.indexOf(";", index+1) + 1;
                else
                    nextindex = index + i + 1;
                // Extract string
                String oneparam = oldparams.substring(index, nextindex);
                if (hasPreParam)
                    sb.append(",");
                sb.append(transformIntoSootValueType(oneparam));
                hasPreParam = true;
                index = nextindex;
            }
            // normal one-character parameter
            else {
                String oneparam = String.format("%c", param);
                if (hasPreParam)
                    sb.append(",");
                sb.append(transformIntoSootValueType(oneparam));
                hasPreParam = true;
                index++;
            }
        }
        sb.append(")");
        
        sb.append(">");
        return sb.toString();
    }
    
    /**
     * Transform only one single type, including array
     * 
     * V    --> void
     * I    --> int
     * Z    --> boolean
     * J    --> long
     * B    --> byte
     * [B   --> byte[]
     * [[B  --> byte[][]
     * Ljava/lang/Thread; --> java.lang.Thread
     * 
     * @param value
     * @return
     */
    public static String transformIntoSootValueType(String value) {
        StringBuilder sb = new StringBuilder();
        
        // Array needs to be handled recursively
        if (value.startsWith("[")) {
            // Find the first index not with "["
            int i;
            for (i = 1; i < 100; i++) { //intentially use a large but not infinate value
                char temp = value.charAt(i);
                if (temp != '[')
                    break;
            }
            // Generate the format
            value = value.substring(i);
            sb.append(transformIntoSootValueType(value)); //recursive
            for ( ; i > 0; i--) {
                sb.append("[]");
            }
        }
        // class
        else if (value.startsWith("L") &&
                 value.endsWith(";")) {
            value = value.replace("/", ".");
            sb.append(value.substring(1, value.length()-1));
        }
        else if (value.equals("V")) {
            sb.append("void");
        }
        else if (value.equals("I")) {
            sb.append("int");
        }
        else if (value.equals("Z")) {
            sb.append("boolean");
        }
        else if (value.equals("J")) {
            sb.append("long");
        }
        else if (value.equals("B")) {
            sb.append("byte");
        }
        else if (value.equals("F")) {
            sb.append("float");
        }
        else if (value.equals("D")) {
            sb.append("double");
        }
        else if (value.equals("C")) {
            sb.append("char");
        }
        else if (value.equals("S")) {
            sb.append("short");
        }
        // TODO
        else {
            System.err.println("Havn't handled this type: "+value);
        }
        
        return sb.toString();
    }
    
    /**
     * 
     * @param unit
     * @return null if no InvokeExpr
     */
    public static InvokeExpr extractInvokeExprFromUnit(Unit unit) {
        if (unit == null)
            return null;
        
        InvokeExpr expr = null;
        
        if (unit instanceof DefinitionStmt) {
            DefinitionStmt ds = (DefinitionStmt) unit;
            Value ds_right = ds.getRightOp();
            if (ds_right instanceof InvokeExpr) {
                expr = (InvokeExpr) ds_right;
            }
        }
        else if (unit instanceof InvokeStmt) {
            InvokeStmt is = (InvokeStmt) unit;
            expr = is.getInvokeExpr();
        }
        /*
         * How to handle the following stmt:
         * if $z3 == 0 goto $r34 = staticinvoke <org.apache.commons.vfs2.provider.ftp.FtpFileSystemConfigBuilder: org.apache.commons.vfs2.provider.ftp.FtpFileSystemConfigBuilder getInstance()>()
         */
        else if (unit instanceof IfStmt) {
            IfStmt is = (IfStmt) unit;
            Unit tgt_stmt = is.getTarget();
            return extractInvokeExprFromUnit(tgt_stmt);
        }
        /*
         * goto [?= staticinvoke <java.lang.Thread: void setDefaultUncaughtExceptionHandler(java.lang.Thread$UncaughtExceptionHandler)>(r0)]
         */
        else if (unit instanceof GotoStmt) {
            GotoStmt gotostmt = (GotoStmt) unit;
            Unit tgt_gotostmt = gotostmt.getTarget();
            return extractInvokeExprFromUnit(tgt_gotostmt);
        }
        /*
         * TODO not perfect handling here
         * 
         * com.itau.pers
         * tableswitch(b36_2) {     case 0: goto b32_5 = Phi(b32_3, b32_4);     
         * default: goto goto [?= r42 = virtualinvoke r36.<o.aAO: android.content.SharedPreferences$Editor edit()>()]; }
         * 
         * lookupswitch(b37_2) {     case 90: goto b32_5 = Phi(b32_3, b32_4);     
         * default: goto goto [?= r43 = virtualinvoke r36.<o.aAO: android.content.SharedPreferences$Editor edit()>()]; }
         */
        else if (unit instanceof TableSwitchStmt || unit instanceof LookupSwitchStmt) {
            Unit defaultstmt;
            List<Unit> tgt_stmts;
            
            if (unit instanceof TableSwitchStmt) {
                TableSwitchStmt switchstmt = (TableSwitchStmt) unit;
                defaultstmt = switchstmt.getDefaultTarget();
                tgt_stmts = switchstmt.getTargets();
            } else {
                LookupSwitchStmt switchstmt = (LookupSwitchStmt) unit;
                defaultstmt = switchstmt.getDefaultTarget();
                tgt_stmts = switchstmt.getTargets();
            }
            
            if (defaultstmt != null && defaultstmt.toString().contains("invoke ")) {
                return extractInvokeExprFromUnit(defaultstmt);
            } else {
                for (Unit tgt_stmt : tgt_stmts) {
                    if (tgt_stmt.toString().contains("invoke ")) {
                        return extractInvokeExprFromUnit(tgt_stmt);
                    }
                }
            }
        }
        /*
         * TODO Some other places may also have problems
         */
        else {
            if (unit.toString().contains("invoke ")) {
                MyUtil.printlnOutput(String.format("%s Not a InvokeExpr, but contains invoke: %s", 
                        MyConstant.ErrorPrefix, unit.toString()),
                        MyConstant.RELEASE);
            }
        }
        
        return expr;
    }
    
    public static boolean isContaintInvokeStmtFromUnit(Unit unit) {
        if (unit == null)
            return false;
        
        String unit_str = unit.toString();
        return unit_str.contains(")>(");
    }
    
    public static DefinitionStmt extractDefStmtFromUnit(Unit unit) {
        if (unit == null)
            return null;
        
        DefinitionStmt stmt = null;
        
        if (unit instanceof DefinitionStmt) {
            stmt = (DefinitionStmt)unit;
        }
        else if (unit instanceof IfStmt) {
            IfStmt is = (IfStmt) unit;
            Unit tgt_stmt = is.getTarget();
            if (tgt_stmt instanceof DefinitionStmt)
                stmt = (DefinitionStmt)tgt_stmt;
        }
        
        return stmt;
    }
    
    /**
     * 
     * @param unit
     * @return null if no Return Value
     */
    public static Value extractReturnValueFromUnit(Unit unit) {
        if (unit == null)
            return null;
        
        Value value = null;
        
        if (unit instanceof ReturnStmt) {
            ReturnStmt tgt_rs = (ReturnStmt)unit;
            value = tgt_rs.getOp();
        }
        /*
         * goto [?= return i1]
         * goto [?= staticinvoke <org.apache.commons.vfs2.util.UserAuthenticatorUtils: void cleanup(org.apache.commons.vfs2.UserAuthenticationData)>(r17)]
         * goto [?= i3 = i3 + 1]
         */
        else if (unit instanceof GotoStmt) {
            GotoStmt gotostmt = (GotoStmt) unit;
            Unit gototgt = gotostmt.getTarget();
            return extractReturnValueFromUnit(gototgt);
        }
        else {
            if (unit.toString().contains("return ")) {
                MyUtil.printlnOutput(String.format("%s Not a return stmt, but contains return: %s", 
                        MyConstant.ErrorPrefix, unit.toString()),
                        MyConstant.RELEASE);
            }
        }
        
        return value;
    }
    
    /**
     * Extract (and remove) a cross edge from a list of BDGEdge.
     * 
     * If there are multiple cross edges, we return the first one.
     * But this should be illegal!
     * 
     * @param edges
     * @return null if there is no cross edge
     */
    public static BDGEdge extractANDremoveCrossEdge(List<BDGEdge> edges) {
        BDGEdge result = null;
        
        for (int i = 0; i < edges.size(); i++) {
            BDGEdge edge = edges.get(i);
            
            if (edge.getType() == BDGEdgeType.CROSS_EDGE) {
                result = edge;   //Actually no particular order which is the first
                edges.remove(i);
                
                /*
                 * We need to remove all cross edges.
                 * Otherwise, if one node has two or more cross nodes.
                 */
                //break;//TODO we do not analyze any further and let outside decide
            }
        }
        
        return result;
    }
    
    /**
     * <com.sina.weibo.media.a.c: void <init>(java.lang.String)>
     * -->
     * "c"
     * 
     * <jnamed: void serveTCP(java.net.InetAddress,int)>
     * -->
     * "jnamed"
     * 
     * @param msig
     * @return
     */
    public static String extractClassNameFromMSig(String msig) {
        String first = msig.split(": ", 2)[0];  //"<com.sina.weibo.media.a.c"
        
        int lastindex = first.lastIndexOf(".");
        
        if (lastindex == -1)//"<jnamed"
            return first.substring(1, first.length());
        else
            return first.substring(lastindex+1, first.length());
    }
    
    /**
     * <com.sina.weibo.media.a.c: void <init>(java.lang.String)>
     * -->
     * "com.sina.weibo.media.a.c"
     * 
     * @param msig
     * @return
     */
    public static String extractFullClassFromMSig(String msig) {
        String first = msig.split(": ", 2)[0];  //"<com.sina.weibo.media.a.c"
        
        return first.substring(1, first.length());
    }
    
    /**
     * <com.sina.weibo.media.a.c: void <init>(java.lang.String)>
     * -->
     * "<init>"
     * 
     * <uk.co.sevendigital.android.library.stream.SDIMediaServer: java.net.ServerSocket b(int,int)>
     * -->
     * "b"
     * 
     * @param msig
     * @return
     */
    public static String extractMethodFromMSig(String msig) {
        String second = msig.split(": ", 2)[1];  //"void <init>(java.lang.String)>"
        
        int begindex = second.indexOf(" ");
        int endindex = second.indexOf("(");
        
        return second.substring(begindex+1, endindex);
    }
    
    public static SootMethod findInstanceInitMethod(
            SootClass mclass, String submsig) {
        if (mclass == null)
            return null;
        
        SootMethod result = null;
        
        Iterator<SootMethod> method_iter = mclass.methodIterator();
        while (method_iter.hasNext()) {
            SootMethod method = method_iter.next();
            if (method.getSubSignature().equals(submsig)) {
                result = method;
                break;
            }
        }
        
        return result;
    }
    
    /**
     * 
     * @param method
     * @param msig Soot format of the method signature, sub signature is also fine
     * @return
     * 
     * TODO might have bug if signature is correct but object instance is not right
     * This could happen for ForwardTainter...
     */
    public static List<Unit> findCallerUnits(SootMethod method, String msig) {
        List<Unit> units = new ArrayList<Unit>();
        
        if (!method.isConcrete())
            return units;
        
        Body body = MyUtil.retrieveActiveSSABody(method);
        if (body == null)
            return units;
        
        Iterator<Unit> iter_u = body.getUnits().iterator();
        
        while (iter_u.hasNext()) {
            Unit unit = iter_u.next();
            if (unit instanceof InvokeStmt || unit instanceof AssignStmt) {
                String unitstr = unit.toString();
                if (unitstr.contains(msig)) {
                    units.add(unit);
                }
            }
        }
        
        return units;
    }
    
    public static void printlnOutput(String output, int rank) {
        if (rank >= MyConstant.CURRENTRANK)
            System.out.println(output);
    }
    
    public static void printOutput(String output, int rank) {
        if (rank >= MyConstant.CURRENTRANK)
            System.out.print(output);
    }
    
    public static void printlnOutput(String output) {
        printlnOutput(output, MyConstant.CURRENTRANK);
    }
    
    public static void printOutput(String output) {
        printOutput(output, MyConstant.CURRENTRANK);
    }
    
    /**
     * From https://stackoverflow.com/questions/14018478/string-contains-ignore-case
     * 
     * @param str
     * @param searchStr
     * @return
     */
    public static boolean containsIgnoreCase(String str, String searchStr) {
        if (str == null || searchStr == null)
            return false;

        final int length = searchStr.length();
        if (length == 0)
            return true;

        for (int i = str.length() - length; i >= 0; i--) {
            if (str.regionMatches(true, i, searchStr, 0, length))
                return true;
        }
        return false;
    }
    
    /**
     * Also remove the internal class name.
     * "CameraMirrorActivity$c" --> 'CameraMirrorActivity' 
     * 
     * @param string
     * @param len
     * @return
     */
    public static String cutShortClassString(String string, int len) {
        /*
         * see https://bitbucket.org/zout/backdroid/issues/35/output-the-tag-well
         */
        if (string.contains(" "))
            return "";
        if (string.contains("(") || string.contains(")"))
            return "";
        if (string.contains("[") || string.contains("]"))
            return "";
        
        if (string.contains("$"))
            string = string.split("\\$")[0];
        
        if (string.length() < len)  //E.g., len = 3
            return "";
        else
            return string;
    }
    
    /**
     * Two conditions:
     * - method name: onXXX()
     * - class: from four component + Fragment
     * 
     * @param method
     * @return
     */
    public static boolean isEntryMethod(SootMethod method) {
        String mtd_name = method.getName();
        if (!mtd_name.startsWith("on"))
            return false;
        
        SootClass cls_soot = method.getDeclaringClass();
        String cls_name = cls_soot.getName();
        
        /*
         * Check with manifest components
         * TODO Even it is registered in manifest, we should lauch ICC analysis?
         */
        Set<String> maniCompSet = ManifestWorker.v().getManiCompSet();
        if (maniCompSet.contains(cls_name)) {
            return true;
        }
        
        /*
         * Normal way
         * TODO How about fragment?
         */
        String rootcls_name = getRootClsName(method.getDeclaringClass());
        if (rootcls_name.equals("android.app.Application")
                || (rootcls_name.startsWith("android.support.") & rootcls_name.endsWith("Fragment"))
                || rootcls_name.equals("android.app.Fragment")
                || rootcls_name.equals("android.content.BroadcastReceiver")) {
            
            MyUtil.printlnOutput(String.format("%s Detect a potential entry %s using its root class: %s",
                    MyConstant.CriticalPrefix, method.getSignature(), rootcls_name),
                    MyConstant.RELEASE);
            return true;
            
        } else if (rootcls_name.equals("android.app.Activity")
                || rootcls_name.equals("android.app.Service")
                || rootcls_name.equals("android.content.ContentProvider")) {
            
            MyUtil.printlnOutput(String.format("%s Detect a FAILED entry %s using its root class: %s",
                    MyConstant.CriticalPrefix, method.getSignature(), rootcls_name),
                    MyConstant.WARN);
            return false;
        }
        
        return false;
    }
    
    public static String getRootClsName(SootClass initclass) {
        String initname = initclass.getName();
        if (rootClsMap.containsKey(initname))
            return rootClsMap.get(initname);
        
        String rootname;
        SootClass mclass = null;
        do {
            if (mclass == null)
                mclass = initclass; //First time
            else
                mclass = mclass.getSuperclass();
            
            rootname = mclass.getName();
            if (rootname.equals("android.app.Application")
                    || rootname.equals("android.support.v4.app.Fragment")
                    || rootname.equals("android.app.Fragment")
                    || rootname.equals("android.app.Activity")
                    || rootname.equals("android.app.Service")
                    || rootname.equals("android.content.BroadcastReceiver")
                    || rootname.equals("android.content.ContentProvider")) {
                break;
            }
        } while (mclass.hasSuperclass());
        
        rootClsMap.put(initname, rootname);
        
        return rootname;
    }
    
    /**
     * Avoid to repeat generating new SSA body,
     * which causes NoSuchElementException in backwardOneMethod()'s HashChain.getPredOf()
     * 
     * TODO we can set options for Shimple here
     * https://www.sable.mcgill.ca/soot/doc/soot/options/ShimpleOptions.html
     * https://www.sable.mcgill.ca/soot/doc/soot/shimple/ShimpleBody.html
     * TODO https://www.sable.mcgill.ca/soot/doc/soot/shimple/Shimple.html#newBody(soot.Body, java.util.Map)
     * 
     * @param method
     * @return Might be null, so outside must do a check
     */
    public static Body retrieveActiveSSABody(SootMethod method) {
        if (method.hasActiveBody()) {
            return method.getActiveBody();
            
        } else {
            try {
                Body body = method.retrieveActiveBody();
                body = Shimple.v().newBody(body);
                method.setActiveBody(body); //Set is important
                return body;
                
            } catch (RuntimeException e) {
                MyUtil.printlnOutput(String.format("%s retrieveActiveSSABody: %s",
                        MyConstant.ErrorPrefix, Throwables.getStackTraceAsString(e)),
                        MyConstant.WARN);
                return null;
            }
        }
    }
    
    public static boolean isMethodInClass(SootClass cls, String msubsig) {
        boolean isMethodExist = false;
        
        try {
            SootMethod temp_mtd = cls.getMethod(msubsig);
            if (temp_mtd != null)
                isMethodExist = true;
        } catch (Exception e) {
        }
        
        return isMethodExist;
    }
    
    /**
     * It was previously used in MyUtil.hasOverlapInTwoString(cls_search, rootcls_dex)
     * 
     * @param str1
     * @param str2
     * @return
     */
    public static boolean hasOverlapInTwoString(String str1, String str2) {
        if (str1.startsWith(str2))
            return true;
        if (str2.startsWith(str1))
            return true;
        return false;
    }
    
    /**
     * Try to fix a potential Soot bug
     * 
     * @param mClass
     * @param subsig "void initLocalServer(android.content.Context)"
     * @return
     */
    public static SootMethod sootGetMethod(SootClass mClass, String subsig) {
        SootMethod method = null;
        
        try {
            method = mClass.getMethod(subsig);
        }
        /*
         * Then try new signature with an "''"
         * '-wrap0'() in class com.adobe.fas.DataStorage.FASSuggestions
         */
        catch(RuntimeException e) {
            try {
                String new_subsig = subsig.replace(" ", " '").replace("(", "'(");
                method = mClass.getMethod(new_subsig);
                MyUtil.printlnOutput(String.format("%s Special method name: %s",
                        MyConstant.CriticalPrefix, method.getSignature()), MyConstant.RELEASE);
            } catch(RuntimeException e1) {
                MyUtil.printlnOutput(String.format("%s Failed method name: <%s: %s>",
                        MyConstant.ErrorPrefix, mClass.toString(), subsig), MyConstant.RELEASE);
            }
        }
        
        return method;
    }

    /**
     * Use two or three portions
     * 
     * @param cls_name "com.google.android.wearable.beta.app"
     * @return "com.google.android"
     */
    public static String generateRootClsName(String cls_name) {
        String root_name;
        String[] cls_strs = cls_name.split("\\.");
        
        if (cls_strs.length <= 2)
            root_name = cls_strs[0];
        else if (cls_strs.length == 3)
            root_name = String.format("%s.%s", cls_strs[0], cls_strs[1]);
        else
            root_name = String.format("%s.%s.%s", cls_strs[0], cls_strs[1], cls_strs[2]);
        
        return root_name;
    }
    
    /**
     * Use two or three portions.
     * Should not contain the ending "/", because manifest does not contain.
     * 
     * @param cls_name "com.connectsdk.service.RokuService"
     * @return "Lcom/connectsdk"
     */
    public static String generateClsSearchFromJava(String cls_name) {
        String cls_search = null;
        String[] cls_strs = cls_name.split("\\.");
        
        /*
         * Old code
         */
        if (false) {
            if (cls_strs.length <= 2) {
                cls_search = String.format("L%s", cls_strs[0]);
            }
            /*
             * For handling Lcom/heyzap/http for com.heyzap.http.MySSLSocketFactory
             * So that it becomes Lcom/heyzap
             */
            else if (cls_strs.length == 3 || cls_strs.length == 4) {
                cls_search = String.format("L%s/%s", cls_strs[0], cls_strs[1]);
            }
            else {
                try {
                    Path dexFilePath = Paths.get(PortDetector.DEX2JARfile);
                    FileSystem dexZipFs = FileSystems.newFileSystem(dexFilePath, null);
                    
                    String cls_cur = cls_strs[0];
                    for (int i = 0; i < cls_strs.length; i++) {
                        String cls_root = String.format("%s/%s", cls_cur, cls_strs[i+1]);
                        Path root_dir = dexZipFs.getPath(cls_root);
                        DirectoryStream<Path> dir_stream = Files.newDirectoryStream(root_dir);
                        
                        boolean isStop = false;
                        for (Path entry : dir_stream) {
                            if (entry.toString().endsWith(".class")) {
                                isStop = true;
                                break;
                            }
                        }
                        
                        if (isStop) {
                            cls_search = String.format("L%s", cls_root);
                            break;
                        } else {
                            cls_cur = cls_root;
                        }
                    }
                    
                } catch (Exception e) {
                }
                
                if (cls_search == null)
                    cls_search = String.format("L%s/%s", cls_strs[0], cls_strs[1]);
            }
        }
        
        if (cls_strs.length <= 2)
            cls_search = String.format("L%s", cls_strs[0]);
        else if (cls_strs.length == 3)
            cls_search = String.format("L%s/%s", cls_strs[0], cls_strs[1]);
        else if (cls_strs.length == 4)
            cls_search = String.format("L%s/%s/%s", cls_strs[0], cls_strs[1], cls_strs[2]);
        else if (cls_strs.length == 5)
            cls_search = String.format("L%s/%s/%s/%s", cls_strs[0], cls_strs[1], cls_strs[2], cls_strs[3]);
        else
            cls_search = String.format("L%s/%s/%s/%s/%s", cls_strs[0], cls_strs[1], cls_strs[2], cls_strs[3], cls_strs[4]);
        
        return cls_search;
    }
    
    /**
     * Use two to five portions.
     * 
     * @param cls_name "Lcom/lge/app1/fota/popup/FOTAPopups;"
     * @return "Lcom/lge/app1"
     */
    public static String generateClsSearchFromDex(String cls_name) {
        String cls_search = null;
        String[] cls_strs = cls_name.split("/");
        
        if (cls_strs.length <= 2)
            cls_search = String.format("%s", cls_strs[0]);
        else if (cls_strs.length == 3)
            cls_search = String.format("%s/%s", cls_strs[0], cls_strs[1]);
        else if (cls_strs.length == 4)
            cls_search = String.format("%s/%s/%s", cls_strs[0], cls_strs[1], cls_strs[2]);
        else if (cls_strs.length == 5)
            cls_search = String.format("%s/%s/%s/%s", cls_strs[0], cls_strs[1], cls_strs[2], cls_strs[3]);
        else
            cls_search = String.format("%s/%s/%s/%s/%s", cls_strs[0], cls_strs[1], cls_strs[2], cls_strs[3], cls_strs[4]);
        
        return cls_search;
    }
    
}
