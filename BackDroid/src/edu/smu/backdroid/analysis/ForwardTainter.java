package edu.smu.backdroid.analysis;

import soot.Body;
import soot.PatchingChain;
import soot.SootClass;
import soot.SootMethod;
import soot.SootMethodRef;
import soot.Unit;
import soot.Value;
import soot.jimple.DefinitionStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.ReturnStmt;
import edu.smu.backdroid.PortDetector;
import edu.smu.backdroid.structure.CallerContainer;
import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Perform forward taint analysis
 * Use to handle interface/callback search
 * 
 * But only do direct propagation-based taint
 * 
 * @author Daoyuan
 * @since 18-09-04
 */
public class ForwardTainter {
    
    private static ForwardTainter instance;
    
    static {
        ForwardTainter.instance = new ForwardTainter();
    }
    
    public ForwardTainter() {
    }
    
    /**
     * Get an instance of ForwardTainter
     * 
     * @return
     */
    public static ForwardTainter v() {
        return ForwardTainter.instance;
    }
    
    /**
     * 
     * @param init_cls_name com.apptracker.android.module.AppModuleLoader$1
     * @param tgt_msig Somtimes useful: <com.apptracker.android.module.AppModuleLoader$1: void onServerSync(java.util.ArrayList)>
     * @param end_msig <com.apptracker.android.listener.AppListener: void onServerSync(java.util.ArrayList)>
     * @return
     */
    public List<CallerContainer> traceObjectMethod(final String init_cls_name,
            final String tgt_msig, final String end_msig) {
        List<CallerContainer> caller_methods = new ArrayList<CallerContainer>();
        
        /*
         * Locate the <init> methods
         */
        SootClass init_cls = ClassWorker.loadClass(init_cls_name);
        Iterator<SootMethod> init_mtd_iter = init_cls.methodIterator();
        
        while (init_mtd_iter.hasNext()) {
            SootMethod init_mtd = init_mtd_iter.next();
            
            if (init_mtd.isConstructor()) {
                String init_msig = init_mtd.getSignature();
                MyUtil.printlnOutput(String.format(
                        "%s traceObjectMethod finds an init method: %s",
                        MyConstant.NormalPrefix, init_msig), MyConstant.DEBUG);
                
                // Search <init> call sites
                Map<String, StringBuilder> search_objmtds = 
                        MyUtil.transformIntoSearchMethod(init_mtd, true);
                StringBuilder search_dexdump_sb = search_objmtds.get(init_msig);//Just got signature method
                String search_dexdump = MyUtil.sanitizeSS(search_dexdump_sb.toString());
                String cmdcontent = String.format("cat %s " +
                        "| grep -e \"%s\" -e \".*:                                        |\\[.*\\] \" -e \"    #.* : (in L.*;)\" " +
                        "| grep -B 2 -e \"%s\" " +
                        "| grep -e \".*:                                        |\\[.*\\] \" -e \"    #.* : (in L.*;)\" ",
                        PortDetector.DEXDUMPlog, search_dexdump, search_dexdump);
                MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                        MyConstant.ForwardPrefix, cmdcontent), MyConstant.DEBUG);
                
                // Locate <init> call sites in methods
                List<String> res_search_initmtd = MyUtil.grepMethodResult(cmdcontent);
                for (final String one_method : res_search_initmtd) {
                    String one_sootmsig = MyUtil.transformIntoSootMSig(one_method);
                    MyUtil.printlnOutput(String.format(
                            "%s traceObjectMethod locates an init at: %s",
                            MyConstant.NormalPrefix, one_sootmsig), MyConstant.DEBUG);
                    
                    String[] temp_splits = one_sootmsig.split(": ");
                    String one_cname = temp_splits[0].substring(1);
                    String one_subsig = temp_splits[1].substring(0, temp_splits[1].length()-1);
                    
                    SootClass caller_class = 
                            ClassWorker.loadClass(one_cname);//TODO optimize it
                    SootMethod caller_method = 
                            MyUtil.sootGetMethod(caller_class, one_subsig);
                    String caller_msig = caller_method.getSignature();
                    
                    // TODO write crossCallChain and innerCallChain into paper
                    List<String> crossCallChain = new ArrayList<String>();
                    crossCallChain.add(caller_msig);
                    List<String> innerCallChain = new ArrayList<String>();
                    // containerChain will add the init method later
                    List<CallerContainer> containerChain = new ArrayList<CallerContainer>();
                    forwardOneMethod(caller_method, init_cls, true,
                                    init_msig, end_msig, tgt_msig,
                                    null, caller_methods,
                                    crossCallChain, innerCallChain, containerChain);
                }
                
            }
            // static void <clinit>() for com.bsb.hike.ui.HomeActivity
            else if (!init_mtd.isStaticInitializer()) {
                // <init> methods always appear earlier
                break;
            }
        }
        
        //
        // We cannot enforce such policy: If does not find, then use located <init>
        // Because it is possible that there are no callers for some places
        // E.g., <com.apptracker.android.module.AppModuleControllerBase$2: void onServerSync(java.util.ArrayList)>
        //
        
        return caller_methods;
    }

    /**
     * 
     * @param method could be also the field signature; use ";" to represent
     *          <com.bsb.hike.ui.fragments.OfflineDisconnectFragment: com.bsb.hike.ui.fragments.gn f>;
     * @param init_cls
     * @param init_msig could be null (for 2nd-tier method), field, or init msig  
     * @param end_msig
     * @param taintset
     * @param caller_methods
     * @param crossCallChain
     */
    private void forwardOneMethod(SootMethod method, final SootClass init_cls,
            final boolean isFirst, final String init_msig,
            final String end_msig, final String tgt_msig,
            Set<String> taintset, List<CallerContainer> caller_methods,
            List<String> crossCallChain, List<String> innerCallChain,
            List<CallerContainer> containerChain) {
        if (method == null)
            return;
        if (taintset == null)
            taintset = new HashSet<String>();
        String last_taint = null;
        
        Body body = MyUtil.retrieveActiveSSABody(method);
        if (body == null)
            return;
        
        String msig = method.getSignature();
        MyUtil.printlnOutput(String.format("%s ForwardTracing %s",
                MyConstant.ForwardPrefix, msig), MyConstant.WARN);
        
        /**
         * Loop all units
         */
        PatchingChain<Unit> u_chain = body.getUnits();
        Iterator<Unit> iter_u = u_chain.iterator();
        while (iter_u.hasNext()) {
            Unit unit = iter_u.next();
            String unit_str = unit.toString();
            
            /**
             * Build the initial taint using init_msig
             */
            if (init_msig != null && 
                    unit_str.contains(init_msig)) {
                if (false)
                    MyUtil.printlnOutput(String.format("%s ForwardTainting init_msig: %s at %s",
                            MyConstant.NormalPrefix, init_msig, unit_str),
                            MyConstant.DEBUG);
                
                boolean isInvoke = MyUtil.isContaintInvokeStmtFromUnit(unit);
                /*
                 * Init func for init_msig:
                 * specialinvoke $r13.<com.apptracker.android.module.AppModuleLoader$1:
                 *                    void <init>(...)>(r0, r1, z0);
                 * specialinvoke $r2.<com.bsb.hike.s: void <init>()>();
                 * 
                 * Could be also return value:
                 * r1 = virtualinvoke r0.<com.lge.app1.media.NanoHTTPD: com.lge.app1.media.NanoHTTPD$ServerRunnable createServerRunnable(int)>(i0);
                 * if $z3 == 0 goto $r34 = staticinvoke <org.apache.commons.vfs2.provider.ftp.FtpFileSystemConfigBuilder: org.apache.commons.vfs2.provider.ftp.FtpFileSystemConfigBuilder getInstance()>()
                 */
                if (isInvoke) {
                    // For init case
                    if (unit instanceof InvokeStmt) {
                        InvokeStmt is = (InvokeStmt) unit;
                        InvokeExpr ie = is.getInvokeExpr();
                        // See issue #109
                        if (!(ie instanceof InstanceInvokeExpr))
                            continue;
                        InstanceInvokeExpr iie = (InstanceInvokeExpr)ie;
                        Value base = iie.getBase();
                        String base_str = base.toString();
                        
                        MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                                MyConstant.NormalPrefix, base_str, unit_str),
                                MyConstant.DEBUG);
                        taintset.add(base_str);
                        last_taint = base_str;
                        //continue; //Also track inside to handle <com.bsb.hike.s: void run()> 
                    }
                    // For return msig case
                    else {
                        DefinitionStmt ds = MyUtil.extractDefStmtFromUnit(unit);
                        if (ds != null) {
                            Value ds_left = ds.getLeftOp();
                            String ds_left_str = ds_left.toString();
                            
                            MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                                    MyConstant.NormalPrefix, ds_left_str, unit_str),
                                    MyConstant.DEBUG);
                            taintset.add(ds_left_str);
                            last_taint = ds_left_str;
                            continue;   //Have no need to further analyze the method
                        }
                    }
                }
                /*
                 * Field for init_msig:
                 * $r8 = $r7.<com.bsb.hike.ui.fragments.OfflineDisconnectFragment: 
                 *           com.bsb.hike.ui.fragments.gn f>;
                 *           
                 * if $z0 == 0 goto $r2 = r0.<com.heyzap.internal.RetryManager$RetryableTask: com.heyzap.internal.RetryManager retryManager>
                 */
                else {
                    DefinitionStmt ds = MyUtil.extractDefStmtFromUnit(unit);
                    
                    if (ds != null) {
                        Value ds_right = ds.getRightOp();
                        String ds_right_str = ds_right.toString();
                        // Only at this point, field is at the right side!!!
                        if (ds_right_str.contains(init_msig)) {
                            Value ds_left = ds.getLeftOp();
                            String ds_left_str = ds_left.toString();
                            
                            MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                                    MyConstant.NormalPrefix, ds_left_str, unit_str),
                                    MyConstant.DEBUG);
                            taintset.add(ds_left_str);
                            last_taint = ds_left_str;
                            continue;   //Have no need to further analyze
                        }
                    }
                }
            }
            
            if (taintset.isEmpty())
                continue;
            
            /**
             * Then taint set is not empty.
             * We further determine whether this statement is potentially tainted
             */
            boolean isPotentaillyTainted = false;
            for (String taint : taintset) {
                if (unit_str.contains(taint)) {
                    isPotentaillyTainted = true;
                    break;
                }
            }
            if (!isPotentaillyTainted)
                continue;
            
            /** 
             * Then is potentially tainted, although we do not know which one.
             * We first determine whether end_msig is reached!
             */
            // For issue #74: some end_msig has multiple formats
            boolean isEndMSigAppear = false;
            boolean isParaForTaint = false;
            if (unit_str.contains(end_msig)
                    || unit_str.contains(tgt_msig)) {
                isEndMSigAppear = true;
            }
            // TODO could similarly use "android.os.Message" as indicator?
            else if (end_msig.equals("<android.os.Handler: boolean sendMessage(android.os.Message)>")) {
                if (unit_str.contains("<android.os.Messenger: void send(android.os.Message)>")
                        || unit_str.contains("<android.os.Handler: boolean sendEmptyMessage")
                        || unit_str.contains("<android.os.Handler: boolean sendMessage")) {
                    isEndMSigAppear = true;
                }
            }
            // https://stackoverflow.com/questions/13840007/what-exactly-does-the-post-method-do
            // There are also other Runnable handlers:
            // E.g., <android.os.Handler: boolean postAtFrontOfQueue(java.lang.Runnable)>
            // E.g., <android.os.Handler: void removeCallbacks(java.lang.Runnable)>
            // Also, $r5.<java.util.concurrent.ExecutorService: java.util.concurrent.Future submit(java.lang.Runnable)>(r8);
            else if (end_msig.equals("<java.lang.Thread: void start()>")) {
                if (unit_str.contains("invoke")
                        && !unit_str.contains("removeCallbacks")
                        && !unit_str.contains("<init>")
                        && (unit_str.contains("(java.lang.Runnable")
                        || unit_str.contains("java.lang.Runnable)")
                        || unit_str.contains("java.lang.Runnable,"))) {
                    InvokeExpr ie = MyUtil.extractInvokeExprFromUnit(unit);
                    SootMethodRef ie_smr = ie.getMethodRef();
                    SootMethod newmtd = ie_smr.resolve();   //Can resolve to system method
                    String ie_cls_name = newmtd.getDeclaringClass().getName();
                    if (PortDetector.apiClassSet.contains(ie_cls_name)) {
                        isEndMSigAppear = true;
                        isParaForTaint = true;
                        String ie_msig = newmtd.getSignature();
                        MyUtil.printlnOutput(String.format("%s ForwardFinding Signature %s",
                                MyConstant.NormalPrefix, ie_msig),
                                MyConstant.WARN);
                    }
                }
                if (false) {
                    if (unit_str.contains(": void runOnUiThread(java.lang.Runnable)>")
                            || unit_str.contains(": boolean post(java.lang.Runnable)>")
                            || unit_str.contains(": boolean postDelayed(java.lang.Runnable,long)>")) {
                        isEndMSigAppear = true;
                    }
                }
            }
            else if (end_msig.equals("<android.os.AsyncTask: android.os.AsyncTask execute(java.lang.Object[])>")) {
                // Similar to the old version of how we handle start()
                // TODO Also avoid fall into next if
                // TODO Other kinds of execute()
                if (unit_str.contains(": android.os.AsyncTask execute(java.lang.Object[])>")
                        || unit_str.contains(": android.os.AsyncTask executeOnExecutor(java.util.concurrent.Executor,java.lang.Object[])>")
                        || unit_str.contains(": void execute(java.lang.Runnable)")) {
                    isEndMSigAppear = true;
                    if (unit_str.contains(": void execute(java.lang.Runnable)"))
                        isParaForTaint = true;
                }
            }
            // TODO Maybe add one add more parameter to indicate
            else if (end_msig.startsWith("<android.")
                    || end_msig.startsWith("<java.")
                    || end_msig.startsWith("<javax.")) {
                String end_mcls = MyUtil.extractFullClassFromMSig(end_msig); //TODO Do we send in the class
                if (unit_str.contains("invoke")
                        && !unit_str.contains("<init>")
                        && unit_str.contains(end_mcls)) {
                    isEndMSigAppear = true;
                    isParaForTaint = true;
                    InvokeExpr ie = MyUtil.extractInvokeExprFromUnit(unit);
                    SootMethodRef ie_smr = ie.getMethodRef();
                    SootMethod newmtd = ie_smr.resolve();   //Can resolve to system method
                    String ie_msig = newmtd.getSignature();
                    MyUtil.printlnOutput(String.format("%s ForwardFinding Signature %s",
                            MyConstant.NormalPrefix, ie_msig),
                            MyConstant.WARN);
                }
            }
            
            // Confirm the base is tainted
            if (isEndMSigAppear) {
                // Not always the base, such as java.lang.Runnable used
                String[] splits = unit_str.split(".<")[0].split(" ");
                String unit_base_str = splits[splits.length - 1];
                if (taintset.contains(unit_base_str) 
                        || isParaForTaint) {
                    MyUtil.printlnOutput(String.format("%s ForwardEnding %s",
                            MyConstant.NormalPrefix, unit_str),
                            MyConstant.WARN);
                    MyUtil.printlnOutput(String.format("%s ForwardEnding containerChain is: %s",
                            MyConstant.NormalPrefix, containerChain),
                            MyConstant.WARN);
                    CallerContainer last_container = new CallerContainer(unit, method);
                    CallerContainer cur_container = last_container;
                    int i = containerChain.size() - 1;
                    for (; i >= 0; i--) {
                        CallerContainer pre_container = containerChain.get(i);
                        cur_container.addNextContainer(pre_container);
                        cur_container = pre_container;
                    }
                    caller_methods.add(last_container);
                    continue;
                }
            }
            
            /**
             * DefinitionStmt
             * r4 := @parameter7: com.apptracker.android.listener.AppListener;
             * r0 := @this: com.bsb.hike.ui.fragments.cm;
             */
            if (unit instanceof DefinitionStmt) {
                DefinitionStmt ds = (DefinitionStmt) unit;
                Value ds_right = ds.getRightOp();
                String ds_right_str = ds_right.toString();
                
                /*
                 * Transform the format for parameter and this
                 * Before if (taintset.contains(ds_right_str))
                 */
                if (ds_right_str.contains("@parameter")
                        || ds_right_str.contains("@this")) {
                    // Become @parameter7 or @this
                    ds_right_str = ds_right_str.split(": ")[0];
                }
                
                /*
                 * Now we can determine the taint
                 */
                boolean shouldTaintLeft = false;
                if (taintset.contains(ds_right_str)) {
                    shouldTaintLeft = true;
                    
                } else {
                    /*
                     * Handle InvokeExpr
                     * 
                     * TODO Issue: Could have implicit callback
                     */
                    InvokeExpr ie = MyUtil.extractInvokeExprFromUnit(unit);
                    if (ie != null) {
                        MyUtil.printlnOutput(String.format("%s ForwardFinding InvokeFromDef %s",
                                MyConstant.NormalPrefix, unit_str),
                                MyConstant.DEBUG);
                        /*
                         * TODO Refer to the below
                         */
                        SootMethodRef ie_mref = ie.getMethodRef();
                        
                        /*
                         * Potentially resolve the method to system methods
                         * E.g., $r9.<com.apptracker.android.advert.AppVideoView: boolean post(java.lang.Runnable)>($r10)
                         * 
                         * It is ok for SootMethod here to have no "No method source", 
                         *    because only when getting Body only Body will raise exception.
                         */
                        SootMethod newmtd = ie_mref.resolve();
                        
                        // TODO Better filter system methods
                        String ie_cls_name = newmtd.getDeclaringClass().getName();
                        if (PortDetector.apiClassSet.contains(ie_cls_name)) {
                            MyUtil.printlnOutput(String.format("%s ForwardFinding System method %s",
                                    MyConstant.CriticalPrefix, unit_str),
                                    MyConstant.WARN);   //TODO RELEASE
                            continue;
                        }
                        
                        // Create the new set
                        Set<String> newset = new HashSet<String>();
                        
                        // Handle arguments first
                        List<Value> argus = ie.getArgs();
                        for (int i = 0; i < argus.size(); i++) {
                            Value argu = argus.get(i);
                            String argu_str = argu.toString();
                            if (taintset.contains(argu_str)) {
                                //
                                // We should use the method parameter type, not the real one
                                // com.apptracker.android.module.AppModuleLoader$1
                                //String argu_type = argu.getType().toString();
                                // @parameter7: com.apptracker.android.listener.AppListener
                                //String argu_type = newmtd.getParameterType(i).toString();
                                //
                                String newargu = String.format("@parameter%d", i);
                                newset.add(newargu);
                                MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                                        MyConstant.NormalPrefix, newargu, unit_str),
                                        MyConstant.DEBUG);
                            }
                        }
                        
                        // Handle base variable then
                        if (ie instanceof InstanceInvokeExpr) {
                            InstanceInvokeExpr iie = (InstanceInvokeExpr)ie;
                            Value base = iie.getBase();
                            String base_str = base.toString();
                            if (taintset.contains(base_str)) {
                                String newbase = "@this"; 
                                newset.add(newbase);
                                MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                                        MyConstant.NormalPrefix, newbase, unit_str),
                                        MyConstant.DEBUG);
                                /*
                                 * Still need to obtain an accurate SootMethod.
                                 * We use init_cls to help interfaceinvoke and virtualinvoke.
                                 * If method exists, we then prioritize to use it.
                                 * 
                                 * TODO Currently we can do this only for case where base is tainted
                                 * 
                                 * TODO But how to handle implicit methods later?
                                 */
                                if (unit_str.contains("interfaceinvoke")
                                        || unit_str.contains("virtualinvoke")) {
                                    String ie_submsig = newmtd.getSubSignature();
                                    SootMethod is_realmtd = null;
                                    try {
                                        is_realmtd = init_cls.getMethod(ie_submsig);
                                        if (is_realmtd != null)
                                            newmtd = is_realmtd;
                                    } catch (Exception e) {
                                    }
                                }
                            }
                        }
                        
                        // TODO May need to copy field taints into newset
                        // Jump to that method or not
                        if (!newset.isEmpty()) {
                            String newmtd_sig = newmtd.getSignature();
                            
                            if (caller_methods.isEmpty()) {
                                if (innerCallChain.contains(newmtd_sig)) {
                                    MyUtil.printlnOutput(String.format("%s %s: %s; innerCallChain: %s",
                                            MyConstant.ErrorPrefix,
                                            MyConstant.DeadInner_Forward, newmtd_sig, innerCallChain),
                                            MyConstant.WARN);
                                    MyUtil.printlnOutput(
                                            String.format("[DeadLoop]%s---%s---InnerForward",
                                            PortDetector.PKGmust, msig), MyConstant.RELEASE);
                                    continue;
                                }
                                
                                containerChain.add(new CallerContainer(
                                                        unit, method));
                                innerCallChain.add(newmtd_sig);
                                forwardOneMethod(newmtd, init_cls, false,
                                                null, end_msig, tgt_msig,
                                                newset, caller_methods,
                                                crossCallChain, innerCallChain,
                                                containerChain);
                                innerCallChain.remove(innerCallChain.size() - 1);
                                containerChain.remove(containerChain.size() - 1);
                                
                                /*
                                 * TODO handle the 2nd-tier return
                                 */
                                if (newset.contains(MyConstant.ReturnParam)) {
                                    shouldTaintLeft = true;
                                }
                                
                            } else {
                                // Just finish the analysis of the current method
                                MyUtil.printlnOutput(String.format("%s forwardOneMethod already has some results at %s",
                                        MyConstant.NormalPrefix, unit_str),
                                        MyConstant.DEBUG);
                            }
                        }
                    }
                }//--end of else
                
                if (shouldTaintLeft) {
                    Value ds_left = ds.getLeftOp();
                    String ds_left_str = ds_left.toString();
                    
                    taintset.add(ds_left_str);
                    last_taint = ds_left_str;
                    MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                            MyConstant.NormalPrefix, ds_left_str, unit_str),
                            MyConstant.DEBUG);
                }
            }
            /**
             * InvokeStmt
             * virtualinvoke r15.setListener(r4); where r4 is tainted
             * virtualinvoke $r14.<com.hike.transporter.c.b: void a()>(); where $r14 is tainted
             * 
             * Value propagation via init method:
             * specialinvoke $r6.<android.os.Messenger: void <init>(android.os.Handler)>($r7); where $r7 is tainted
             * specialinvoke $r1.<java.lang.Thread: void <init>(java.lang.Runnable,java.lang.String)>(r0, "serverThread");
             * specialinvoke $r6.<java.lang.Thread: void <init>(java.lang.Runnable)>(r0);
             * 
             * Track inside for the thread object's very first <init>
             * specialinvoke $r2.<com.bsb.hike.s: void <init>()>();
             * 
             * TODO when method is implicit
             * virtualinvoke $r5.<com.bsb.hike.db.a: android.os.AsyncTask executeOnExecutor()>($r4, $r3);
             * virtualinvoke $r3.<com.lge.tms.loader.http.HTTPGetRequest$SendGetTask: android.os.AsyncTask executeOnExecutor()>($r5, $r4);
             */
            else if (unit instanceof InvokeStmt) {
                InvokeStmt is = (InvokeStmt) unit;
                InvokeExpr ie = is.getInvokeExpr();
                /*
                 * TODO The above also uses the same
                 */
                SootMethodRef ie_mref = ie.getMethodRef();
                
                /*
                 * Potentially resolve the method to system methods
                 * E.g., $r9.<com.apptracker.android.advert.AppVideoView: boolean post(java.lang.Runnable)>($r10)
                 * 
                 * It is ok for SootMethod here to have no "No method source", 
                 *    because only when getting Body only Body will raise exception.
                 */
                SootMethod newmtd = ie_mref.resolve();
                
                // TODO Better filter system methods
                String ie_cls_name = newmtd.getDeclaringClass().getName();
                if (PortDetector.apiClassSet.contains(ie_cls_name)) {
                    // Use a simple way to propagate values: the taint must be parameter
                    // Sometimes can re-taint: ForwardTainting r0 at specialinvoke r0.<java.lang.Object: void <init>()>()
                    if (unit_str.contains("void <init>")) {
                        InstanceInvokeExpr iie = (InstanceInvokeExpr)ie;
                        Value base = iie.getBase();
                        String base_str = base.toString();
                        taintset.add(base_str);
                        last_taint = base_str;
                        MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                                MyConstant.NormalPrefix, base_str, unit_str),
                                MyConstant.DEBUG);
                    }
                    
                    continue;
                }
                
                // Create the new set
                Set<String> newset = new HashSet<String>();
                
                // Handle arguments first
                List<Value> argus = ie.getArgs();
                for (int i = 0; i < argus.size(); i++) {
                    Value argu = argus.get(i);
                    String argu_str = argu.toString();
                    if (taintset.contains(argu_str)) {
                        //
                        // We should use the method parameter type, not the real one
                        // com.apptracker.android.module.AppModuleLoader$1
                        //String argu_type = argu.getType().toString();
                        // @parameter7: com.apptracker.android.listener.AppListener
                        //String argu_type = newmtd.getParameterType(i).toString();
                        //
                        String newargu = String.format("@parameter%d", i);
                        newset.add(newargu);
                        MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                                MyConstant.NormalPrefix, newargu, unit_str),
                                MyConstant.DEBUG);
                    }
                }
                
                // Handle base variable then
                if (ie instanceof InstanceInvokeExpr) {
                    InstanceInvokeExpr iie = (InstanceInvokeExpr)ie;
                    Value base = iie.getBase();
                    String base_str = base.toString();
                    if (taintset.contains(base_str)) {
                        String newbase = "@this"; 
                        newset.add(newbase);
                        MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                                MyConstant.NormalPrefix, newbase, unit_str),
                                MyConstant.DEBUG);
                        /*
                         * Still need to obtain an accurate SootMethod.
                         * We use init_cls to help interfaceinvoke and virtualinvoke.
                         * If method exists, we then prioritize to use it.
                         * 
                         * TODO Currently we can do this only for case where base is tainted
                         * 
                         * TODO But how to handle implicit methods later?
                         */
                        if (unit_str.contains("interfaceinvoke")
                                || unit_str.contains("virtualinvoke")) {
                            String ie_submsig = newmtd.getSubSignature();
                            SootMethod is_realmtd = null;
                            try {
                                is_realmtd = init_cls.getMethod(ie_submsig);
                                if (is_realmtd != null)
                                    newmtd = is_realmtd;
                            } catch (Exception e) {
                            }
                        }
                    }
                }
                
                // TODO May need to copy field taints into newset
                // Jump to that method or not
                if (!newset.isEmpty()) {
                    String newmtd_sig = newmtd.getSignature();
                    
                    if (caller_methods.isEmpty()) {
                        if (innerCallChain.contains(newmtd_sig)) {
                            MyUtil.printlnOutput(String.format("%s %s: %s; innerCallChain: %s",
                                    MyConstant.ErrorPrefix,
                                    MyConstant.DeadInner_Forward, newmtd_sig, innerCallChain),
                                    MyConstant.WARN);
                            MyUtil.printlnOutput(
                                    String.format("[DeadLoop]%s---%s---InnerForward",
                                    PortDetector.PKGmust, msig), MyConstant.RELEASE);
                            continue;
                        }
                        
                        containerChain.add(new CallerContainer(
                                                unit, method));
                        innerCallChain.add(newmtd_sig);
                        forwardOneMethod(newmtd, init_cls, false,
                                        null, end_msig, tgt_msig,
                                        newset, caller_methods,
                                        crossCallChain, innerCallChain,
                                        containerChain);
                        innerCallChain.remove(innerCallChain.size() - 1);
                        containerChain.remove(containerChain.size() - 1);
                        
                    } else {
                        // Just finish the analysis of the current method
                        MyUtil.printlnOutput(String.format("%s forwardOneMethod already has some results at %s",
                                MyConstant.NormalPrefix, unit_str),
                                MyConstant.DEBUG);
                    }
                }
            }
            /** 
             * We just mark the return value
             */
            else if (unit instanceof ReturnStmt) {
                ReturnStmt rs = (ReturnStmt) unit;
                Value return_value = rs.getOp();
                String return_str = return_value.toString();
                
                if (taintset.contains(return_str)) {
                    MyUtil.printlnOutput(String.format("%s ForwardFinding Return %s",
                            MyConstant.NormalPrefix, return_str),
                            MyConstant.DEBUG);
                    /*
                     * The initial return and 2-tier return is different
                     */
                    // The 1-tier return
                    if (isFirst) {
                        // We search by signature only.
                        Map<String, StringBuilder> search_upmtds = 
                                MyUtil.transformIntoSearchMethod(method, true);
                        StringBuilder search_dexdump_sb = search_upmtds.get(msig);//TODO just get(0)?
                        String search_dexdump = MyUtil.sanitizeSS(search_dexdump_sb.toString());
                        String cmdcontent = String.format("cat %s " +
                                "| grep -e \"%s\" -e \".*:                                        |\\[.*\\] \" -e \"    #.* : (in L.*;)\" " +
                                "| grep -B 2 -e \"%s\" " +
                                "| grep -e \".*:                                        |\\[.*\\] \" -e \"    #.* : (in L.*;)\" ",
                                PortDetector.DEXDUMPlog, search_dexdump, search_dexdump);
                        MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                                MyConstant.ForwardPrefix, cmdcontent), MyConstant.DEBUG);
                        
                        boolean isHandled = false;
                        List<String> res_search_upmtds = MyUtil.grepMethodResult(cmdcontent);
                        for (final String upmtd_str : res_search_upmtds) {
                            // TODO Do we need to set up a limit here?
                            String upmsig_soot = MyUtil.transformIntoSootMSig(upmtd_str);
                            MyUtil.printlnOutput(String.format(
                                    "%s forwardOneMethod locates an up method at: %s",
                                    MyConstant.NormalPrefix, upmsig_soot), MyConstant.DEBUG);
                            
                            if (msig.equals(upmsig_soot))
                                continue;
                            if (crossCallChain.contains(upmsig_soot)) {
                                MyUtil.printlnOutput(String.format("%s %s: %s; crossCallChain: %s",
                                        MyConstant.ErrorPrefix,
                                        MyConstant.DeadCross_Forward, upmsig_soot, crossCallChain),
                                        MyConstant.WARN);
                                MyUtil.printlnOutput(
                                        String.format("[DeadLoop]%s---%s---CrossForward",
                                        PortDetector.PKGmust, msig), MyConstant.RELEASE);
                                continue;
                            }
                            
                            // See also crossCallerMethod()
                            String[] temp_splits = upmsig_soot.split(": ");
                            String upfunc_cname = temp_splits[0].substring(1);
                            String upfunc_subsig = temp_splits[1].substring(0, temp_splits[1].length()-1);
                            
                            SootClass upfunc_class = 
                                    ClassWorker.loadClass(upfunc_cname);//TODO optimize it
                            SootMethod upfunc_method = 
                                    MyUtil.sootGetMethod(upfunc_class, upfunc_subsig);
                            
                            int last_idx = crossCallChain.size() - 1;
                            crossCallChain.add(upmsig_soot);
                            forwardOneMethod(upfunc_method, init_cls, true, //TODO This should be also first time
                                            msig, end_msig, tgt_msig,
                                            null, caller_methods,
                                            crossCallChain, innerCallChain,
                                            new ArrayList<CallerContainer>());//TODO new correct?
                            crossCallChain.subList(last_idx+1, crossCallChain.size())
                                          .clear();//https://stackoverflow.com/a/10798153/197165
                            
                            isHandled = true;
                        }
                        
                        if (!isHandled) {
                            MyUtil.printlnOutput(String.format("%s ForwardFinding Return %s (1st-tier return)",
                                    MyConstant.ErrorPrefix, return_str),
                                    MyConstant.RELEASE);
                        }
                    }
                    // The 2-tier return
                    else {
                        taintset.add(MyConstant.ReturnParam);
                        last_taint = MyConstant.ReturnParam;
                        MyUtil.printlnOutput(String.format("%s ForwardTainting %s at %s",
                                MyConstant.NormalPrefix, MyConstant.ReturnParam, unit_str),
                                MyConstant.DEBUG);
                    }
                }
            }
            
        }//--end of while
        
        /**
         * Further handling, if there are instance/static fields
         * Only catching the last one should be ok.
         * 
         * TODO Issue: actually need to search up method!!!
         */
        if (caller_methods.isEmpty() && 
                last_taint != null && last_taint.endsWith(">")) {
            MyUtil.printlnOutput(String.format("%s ForwardCatching %s that requires more analysis",
                    MyConstant.ForwardPrefix, last_taint),
                    MyConstant.DEBUG);
            
            // Use FieldWorker to search field funcs
            if (!last_taint.startsWith("<"))
                last_taint = "<" + last_taint.split(".<")[1];
            Set<String> dexdumpfuncs = FieldWorker.staticSearchFieldFuncs(last_taint);
            
            // Locate and search the function for field
            for (String dexdumpfunc : dexdumpfuncs) {
                // TODO If we have detected one, then no need to analyze other field funcs?
                if (!caller_methods.isEmpty())
                    break;
                
                String fieldfunc_soot = MyUtil.transformIntoSootMSig(dexdumpfunc);
                MyUtil.printlnOutput(String.format("%s ForwardFielding func: %s",
                        MyConstant.NormalPrefix, fieldfunc_soot),
                        MyConstant.DEBUG);
                
                if (msig.equals(fieldfunc_soot))
                    continue;
                if (crossCallChain.contains(fieldfunc_soot)) {
                    MyUtil.printlnOutput(String.format("%s %s: %s; crossCallChain: %s",
                            MyConstant.ErrorPrefix,
                            MyConstant.DeadCross_Forward, fieldfunc_soot, crossCallChain),
                            MyConstant.WARN);
                    MyUtil.printlnOutput(
                            String.format("[DeadLoop]%s---%s---CrossForward",
                            PortDetector.PKGmust, msig), MyConstant.RELEASE);
                    continue;
                }
                
                // See also crossCallerMethod()
                String[] temp_splits = fieldfunc_soot.split(": ");
                String fieldfunc_cname = temp_splits[0].substring(1);
                String fieldfunc_subsig = temp_splits[1].substring(0, temp_splits[1].length()-1);
                
                SootClass fieldfunc_class = 
                        ClassWorker.loadClass(fieldfunc_cname);
                SootMethod field_method = 
                        MyUtil.sootGetMethod(fieldfunc_class, fieldfunc_subsig);
                
                // Real search
                int last_idx_container = containerChain.size() - 1;
                containerChain.add(new CallerContainer(
                        MyConstant.NOP_STMT, method));//TODO src_unit here correct? Also affect ForwardWorker
                int last_idx_cross = crossCallChain.size() - 1;
                crossCallChain.add(fieldfunc_soot);
                forwardOneMethod(field_method, init_cls, true, //TODO This should be also first time
                                last_taint, end_msig, tgt_msig,
                                null, caller_methods,
                                crossCallChain, innerCallChain,
                                containerChain);
                crossCallChain.subList(last_idx_cross+1, crossCallChain.size())
                              .clear();//https://stackoverflow.com/a/10798153/197165
                containerChain.subList(last_idx_container+1, containerChain.size())
                              .clear();//For switching to next field func
            }
        }
        
        MyUtil.printlnOutput(String.format("%s ExitTracing %s",
                MyConstant.BackPrefix, method.getSignature()),
                MyConstant.WARN);
    }

}
