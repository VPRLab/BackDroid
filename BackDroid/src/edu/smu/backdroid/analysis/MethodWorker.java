package edu.smu.backdroid.analysis;

import edu.smu.backdroid.PortDetector;
import edu.smu.backdroid.graph.BDG;
import edu.smu.backdroid.graph.BDGUnit;
import edu.smu.backdroid.structure.BoolObj;
import edu.smu.backdroid.structure.CallerContainer;
import edu.smu.backdroid.structure.ParaContainer;
import edu.smu.backdroid.structure.TaintContainer;
import edu.smu.backdroid.structure.TrackContainer;
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
import soot.PatchingChain;
import soot.SootClass;
import soot.SootFieldRef;
import soot.SootMethod;
import soot.SootMethodRef;
import soot.Unit;
import soot.Value;
import soot.jimple.ArrayRef;
import soot.jimple.DefinitionStmt;
import soot.jimple.InstanceFieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.SpecialInvokeExpr;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JVirtualInvokeExpr;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.shimple.PhiExpr;
import soot.toolkits.scalar.ValueUnitPair;

public class MethodWorker {
    
    private static MethodWorker instance;
    
    public static int uniqueMtdNum = 0;
    
    public static int cachedMtdNum = 0;
    
    public static Map<String, Set<CallerContainer>> callerResCache = 
            new HashMap<String, Set<CallerContainer>>();
    
    // TODO write into paper
    private static List<String> innerCallChain = null;
    
    // TODO write into paper
    private static List<String> crossCallChain = null;
    
    private static boolean isCurrentReachable;
    
    private static Set<String> liveEntryMethods;
    
    private static Set<String> deadEntryMethods;

    static {
        MethodWorker.instance = new MethodWorker();
    }
    
    public MethodWorker() {
    }
    
    /**
     * Get an instance of MethodWorker
     * 
     * @return
     */
    public static MethodWorker v() {
        return MethodWorker.instance;
    }
    
    /**
     * The main function for backward slicing
     * 
     * @param unit The initial target unit
     * @param body The method containing the target unit
     * @param bdg  The associated BDG object
     */
    public boolean backwardSlicing(Unit unit, Body body, BDG bdg) {
        String msig = body.getMethod().getSignature();
        boolean result = bdg.addInitNode(unit, msig);
        if (!result)
            return false;
        
        // TODO
        if (msig.startsWith(MyConstant.Facebook_SDK)) {
            MyUtil.printlnOutput(String.format("%s Facebook SDK: %s",
                    MyConstant.ErrorPrefix, msig), MyConstant.RELEASE);
        }
        
        /*
         * Default is not reachable
         * crossCallerMethod() may set it to true
         */
        isCurrentReachable = false;
        liveEntryMethods = new HashSet<String>();
        deadEntryMethods = new HashSet<String>();
        
        /*
         * A lot of iterative process
         */
        crossCallChain = new ArrayList<String>();
        crossCallChain.add(msig);                   //TODO newly added after commit 954fb9c
        innerCallChain = new ArrayList<String>();   //TODO newly added after commit 954fb9c
        backwardOneMethod(unit, msig, body, bdg, false, null);
        
        /*
         * Handle uninitialized static fields
         */
        finalHandleStaticFields(bdg);
        
        if (liveEntryMethods.size() >= MyConstant.MAX_LIVE_ENTRYR_NUM) {
            MyUtil.printlnOutput(String.format("[LiveEntryNum]%s---%s---%s",
                    PortDetector.PKGmust, msig, liveEntryMethods.size()), 
                    MyConstant.RELEASE);
        }
        if (deadEntryMethods.size() >= MyConstant.MAX_DEAD_ENTRYR_NUM) {
            MyUtil.printlnOutput(String.format("[DeadEntryNum]%s---%s---%s",
                    PortDetector.PKGmust, msig, deadEntryMethods.size()), 
                    MyConstant.RELEASE);
        }
        
        return isCurrentReachable;
    }

    /**
     * The real function for backward slicing
     * 
     * Do we need to remove taints?
     * Static fields must be removed!
     * 
     * TODO Static fields may appear in any function
     * TODO Shall use "search" to locate which methods contain a field
     * 
     * @param unit
     * @param msig
     * @param body
     * @param bdg
     * @param isStaticTrack whether it is in the static track
     * @see backwardUnit below
     */
    private void backwardOneMethod(Unit unit, String msig, Body body, BDG bdg,
            final boolean isStaticTrack, final CallerContainer nextContainer) {
        /*
         * First check currentEntryNum
         */
        if (liveEntryMethods.size() >= MyConstant.MAX_LIVE_ENTRYR_NUM)
            return;
        if (deadEntryMethods.size() >= MyConstant.MAX_DEAD_ENTRYR_NUM)
            return;
        
        if (body == null || bdg == null)
            return;
        
        MyUtil.printlnOutput(String.format("%s Analyzing %s in backwardOneMethod",
                MyConstant.ForwardPrefix, msig),
                MyConstant.WARN);
        
        // TODO should have a CFG here, even with the SSA?
        // No need for isStaticTrack
        PatchingChain<Unit> u_chain = body.getUnits();
        
        // For set a normal edge or a return edge
        BoolObj isReturn = new BoolObj();
        
        /**
         * If unit is null, it means we need to taint the return statement.
         */
        boolean isFromInside = false;
        if (unit == null || unit.equals(MyConstant.FLAG_STMT)) {
            isFromInside = true;
            isReturn.setValue(true);
            
            // Find the return unit, which may not be the last one
            if (unit == null) {
                unit = findReturnUnit(u_chain);
                
                Value returnvalue = MyUtil.extractReturnValueFromUnit(unit);
                if (returnvalue != null) {
                    bdg.addNormalNode(unit, msig, isReturn, isStaticTrack);
                    bdg.addTaintValue(returnvalue, msig);
                    MyUtil.printlnOutput(String.format("%s The return stmt value: %s",
                            MyConstant.NormalPrefix, returnvalue.toString()),
                            MyConstant.DEBUG);
                    
                } else {
                    // TODO "void" also fall into this branch
                    MyUtil.printlnOutput(String.format("%s Cannot find a return stmt: %s", 
                            MyConstant.ErrorPrefix, unit.toString()),
                            MyConstant.RELEASE);
                }
            }
            // FLAG_STMT case has no need to taint the return var
            else {
                // TODO we start from the last Unit for the FLAG_STMT case
                unit = u_chain.getLast();
            }
        }
        if (unit.equals(MyConstant.NOP_STMT)) {
            unit = u_chain.getLast();
        }
        
        /**
         * Loop the previous units
         * TODO should have a CFG here
         */
        Unit cur_unit, pre_unit;
        cur_unit = unit;
        while (true) {
            // The last statement is basically "return", so no worry for not catching it
            // Always "return;" for <clinit>
            pre_unit = u_chain.getPredOf(cur_unit);
            if (pre_unit == null)
                break;
            
            //
            // TODO Do we need to retrieve the taint set each time?
            //
            Set<String> taintset = bdg.getTaintSet(msig);
            Set<String> fieldset = bdg.getTaintSet(MyConstant.GLOBALFIELD);
            // TODO Write into paper. Also avoid analyzing rest of statements
            if (taintset.isEmpty() && fieldset.isEmpty()) {
                MyUtil.printlnOutput(String.format("%s Avoid analyzing %s, because taint set is empty",
                        MyConstant.NormalPrefix, msig),
                        MyConstant.DEBUG);
                break;
            }
            
            boolean isThisStmtTainted = false;
            
            /**
             * DefinitionStmt: $i0 = r0.<com.kugou.android.dlna.d.b.a: int c>;
             * AssignStmt belongs to DefinitionStmt: r0.<com.kugou.android.dlna.d.b.a: int c> = i0
             * 
             * $i3 = 8000 + $i2;
             */
            if (pre_unit instanceof DefinitionStmt) {
                DefinitionStmt ds = (DefinitionStmt) pre_unit;
                Value ds_left = ds.getLeftOp();
                String ds_left_str = ds_left.toString();
                boolean isNoNeedTaint = false;  //For InstanceFieldRef
                
                //
                // Just change ds_left_str a little bit
                // Note that we do not change ds_left.
                // So bdg.removeTaintValue(ds_left, msig) below still works.
                //
                /*
                 * Special handling for Array:
                 * $r0[3] = 2612;
                 * <com.kugou.android.mediatransfer.pctransfer.socket.a: int[] b> = $r0;
                 */
                if (ds_left instanceof ArrayRef) {
                    ArrayRef ar = (ArrayRef) ds_left;
                    Value ar_base  = ar.getBase();
                    ds_left_str = ar_base.toString();//"$r0"
                }
                /*
                 * InstanceFieldRef
                 * r0.<com.studiosol.utillibrary.IO.NanoHTTPD: int myPort> = i0;
                 * Fix issue #51
                 * 
                 * The corresponding field signature must be in the SET already
                 */
                else if (ds_left instanceof InstanceFieldRef) {
                    InstanceFieldRef ifr = (InstanceFieldRef) ds_left;
                    Value ifr_base = ifr.getBase();
                    ds_left_str = ifr_base.toString();//"r0"
                    
                    SootFieldRef sfr = ifr.getFieldRef();
                    String sfr_sig = sfr.getSignature();//TODO field class hierarchy
                    Set<String> objFieldSet = bdg.getObjectFieldSet();//TODO move like other two set?
                    if (!objFieldSet.contains(sfr_sig))
                        isNoNeedTaint = true;
                }
                
                if ((!isNoNeedTaint) && 
                        (taintset.contains(ds_left_str) 
                                || fieldset.contains(ds_left_str))) {
                    Value ds_right = ds.getRightOp();
                    
                    /*
                     * Add this unit into the graph
                     */
                    BDGUnit node;
                    if (isFromInside && pre_unit.toString().startsWith("r0 := @this")) {
                        BDGUnit lastnode = bdg.getLastNode(isStaticTrack);
                        String last_msig = lastnode.getMSig();
                        if (!last_msig.equals(msig))//Meaning this node is the only node in msig
                            node = lastnode;
                        else
                            node = bdg.addNormalNode(pre_unit, msig, isReturn, isStaticTrack);
                    } else {
                        node = bdg.addNormalNode(pre_unit, msig, isReturn, isStaticTrack);
                    }
                    
                    /*
                     * Remove the taint. TODO other places?
                     * Better to put before the addTaintValue
                     */
                    bdg.removeTaintValue(ds_left, msig);
                    
                    /*
                     * We by default taint the parameters here?
                     * It may be over-tainted, e,g, InvokeExpr and PhiExpr below.
                     */
                    bdg.addTaintValue(ds_right, msig);
                    isThisStmtTainted = true;
                    
                    /*
                     * Forward analysis later can help improve the precision.
                     * Especially for method callsites we cannot determine yet
                     * Like $i0 = virtualinvoke $r2.<com.hike.transporter.b.a: int c()>()
                     * 
                     * Do we need to jump to that method?
                     * Yes, for this kind of return statement.
                     * Because the method may have some fields.
                     * We need to know which fields are needed to taint.
                     * 
                     * -- $i0 = staticinvoke <com.kugou.framework.e.b.b.a: int c()>();
                     * 
                     * -- $i1 = staticinvoke <com.afollestad.neuron.Terminal: int access$000(com.afollestad.neuron.Terminal)>($r5);
                     *    We shall build a relationship between $i1 and $r5
                     */
                    if (ds_right instanceof InvokeExpr) {
                        MyUtil.printlnOutput(String.format("%s Having one InvokeExpr: %s",
                                MyConstant.NormalPrefix, ds_right.toString()),
                                MyConstant.DEBUG);
                        InvokeExpr raw_expr = (InvokeExpr)ds_right;
                        SootMethod raw_mthd = null;
                        try {
                            raw_mthd = raw_expr.getMethod();
                        } catch (Exception e) {
                            /*
                             * com.kms.timbrfull
                             * 
                             * Class com.kms.kmsshared.DefaultActionHandler$ActionType$KMSApplication$CustomLicensingWrapper 
                             * doesn't have method Ccgcot([java.lang.String])
                             */
                            e.printStackTrace();
                            return; //TODO we simply return now
                        }
                        
                        //
                        // TODO filter non-app class
                        // TODO shall have a standalone function for doing this
                        // e.g., java.util.AbstractMap$SimpleEntry
                        //
                        String raw_cls_name = raw_mthd.getDeclaringClass().getName();
                        if (PortDetector.apiClassSet.contains(raw_cls_name)) {
                            // Do nothing
                        } else {
                            //
                            // Find the real method
                            // TODO if have too many, we simply do not trace this?
                            // TODO Because it means a common method
                            //
                            SootMethod real_mthd = MyUtil.findRealMethod(raw_expr);
                            
                            // Resolve the method body
                            Body invokebody = MyUtil.retrieveActiveSSABody(real_mthd);
                            if (invokebody == null) {
                                MyUtil.printlnOutput(String.format("%s Skipping a unresolvable InvokeExpr: %s",
                                        MyConstant.ErrorPrefix, ds_right.toString()),
                                        MyConstant.RELEASE);
                                cur_unit = pre_unit;
                                continue;
                            }
                            
                            // 
                            // Avoid the dead method loop
                            // Use the call chain to avoid more complicated method loop
                            // TODO See also ForwardTainter how to handle it?
                            //
                            String real_mthd_sig = real_mthd.getSignature();
                            if (innerCallChain.contains(real_mthd_sig)) {
                                MyUtil.printlnOutput(String.format("%s %s: %s",
                                        MyConstant.ErrorPrefix,
                                        MyConstant.DeadInner_Backward, real_mthd_sig),
                                        MyConstant.WARN);
                                MyUtil.printlnOutput(
                                        String.format("[DeadLoop]%s---%s---InnerBackward",
                                        PortDetector.PKGmust, msig), MyConstant.RELEASE);
                                cur_unit = pre_unit;
                                continue;
                            } else {
                                innerCallChain.add(real_mthd_sig);
                            }
                            
                            // TODO Do we need to mark whether the parameter is tainted?
                            // TODO Again, the instance field may be complicated
                            backwardOneMethod(null, real_mthd_sig, invokebody,
                                    bdg, isStaticTrack, nextContainer);
                            
                            innerCallChain.remove(innerCallChain.size() - 1);
                            MyUtil.printlnOutput(String.format("%s Back to the previous %s",
                                    MyConstant.BackPrefix, msig),
                                    MyConstant.WARN);
                            
                            //
                            // Add a return edge here
                            // And set it to be the last node
                            //
                            bdg.createSpecialBDGEdge(node, isStaticTrack);
                            bdg.setLastNode(node, isStaticTrack);
                        }
                    }
                    /*
                     * i8_1 = Phi(i8, i8_2)
                     * We need to fix: add Phi(i8, i8_2) to the method taint set.
                     */
                    else if (ds_right instanceof PhiExpr) {
                        MyUtil.printlnOutput(String.format("%s Having one PhiExpr: %s",
                                MyConstant.NormalPrefix, ds_right.toString()),
                                MyConstant.DEBUG);
                        PhiExpr phi_expr = (PhiExpr)ds_right;
                        
                        List<ValueUnitPair> phi_vup_args = phi_expr.getArgs();
                        for (ValueUnitPair phi_vup_arg : phi_vup_args) {
                            Value phi_arg = phi_vup_arg.getValue();
                            bdg.addTaintValue(phi_arg, msig);
                        }
                        
                        // TODO haven't analyzed predecessor Units
                    }
                    
                }//--end of tainted
            }//--end of DefinitionStmt
            
            /**
             * Only the function invocation, different from DefinitionStmt
             * TODO Just record them here, because we will later do forward analysis.
             * TODO How about the field? If the invoke method contains the field?
             * 
             * Determine by all or only the instance variable?
             * We currently only determine by the base instance variable.
             * 
             * TODO Just handle <init> or not?
             * 
             * specialinvoke $r8.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>($r9, $i0);
             * 
             * $r8 = new java.net.InetSocketAddress;
             * $r9 = r0.<hu.tagsoft.ttorrent.webserver.a.j: java.lang.String a>;
             * $i0 = r0.<hu.tagsoft.ttorrent.webserver.a.j: int b>;
             * specialinvoke $r8.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>($r9, $i0);
             * r3 = $r8;
             * 
             * TRUE{{specialinvoke r3.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>("127.0.0.1", @parameter0: int + 0)}}
             */
            else if (pre_unit instanceof InvokeStmt) {
                InvokeStmt is = (InvokeStmt) pre_unit;
                InvokeExpr ie = is.getInvokeExpr();
                
                //
                // All several other InvokeExpr extend from InstanceInvokeExpr:
                // InterfaceInvokeExpr, SpecialInvokeExpr, VirtualInvokeExpr
                // TODO other InvokeExpr cases:
                // https://www.sable.mcgill.ca/soot/doc/soot/jimple/InvokeExpr.html
                //
                if (ie instanceof InstanceInvokeExpr) {
                    InstanceInvokeExpr iie = (InstanceInvokeExpr)ie;
                    Value base = iie.getBase();
                    
                    // We only determine by the base variable
                    if (taintset.contains(base.toString())) {
                        // Add this unit into the graph
                        BDGUnit node = bdg.addNormalNode(pre_unit, msig, isReturn, isStaticTrack);
                        isThisStmtTainted = true;
                        
                        /*
                         * Backward this method for taint object's fields
                         */
                        SootMethod raw_mthd = ie.getMethod();
                        String raw_cls_name = raw_mthd.getDeclaringClass().getName();
                        if (PortDetector.apiClassSet.contains(raw_cls_name)) {
                            // Taint all parameters
                            bdg.addTaintValue(ie, msig);
                            
                        } else {
                            // Find the real method
                            // TODO if have too many, we simply do not trace this?
                            // TODO Because it means a common method
                            SootMethod real_mthd = MyUtil.findRealMethod(ie);
                            
                            // Resolve the method body
                            Body invokebody = MyUtil.retrieveActiveSSABody(real_mthd);
                            if (invokebody == null) {
                                MyUtil.printlnOutput(String.format("%s Skipping a unresolvable InvokeExpr: %s",
                                        MyConstant.ErrorPrefix, ie.toString()),
                                        MyConstant.RELEASE);
                                cur_unit = pre_unit;
                                continue;
                            }
                            
                            // 
                            // Avoid the dead method loop
                            // Use the call chain to avoid more complicated method loop
                            //
                            String real_mthd_sig = real_mthd.getSignature();
                            if (innerCallChain.contains(real_mthd_sig)) {
                                MyUtil.printlnOutput(String.format("%s %s: %s",
                                        MyConstant.ErrorPrefix,
                                        MyConstant.DeadInner_Backward, real_mthd_sig),
                                        MyConstant.WARN);
                                MyUtil.printlnOutput(
                                        String.format("[DeadLoop]%s---%s---InnerBackward",
                                        PortDetector.PKGmust, msig), MyConstant.RELEASE);
                                cur_unit = pre_unit;
                                continue;
                            } else {
                                innerCallChain.add(real_mthd_sig);
                            }
                            
                            bdg.addTaintValue("r0", real_mthd_sig);
                            //
                            // Try to track the detailed object fields
                            // r0.<com.studiosol.palcomp3.Backend.Cache.MP3LocalServer: java.util.HashMap inputMaps> = $r1;
                            // r0.<com.studiosol.palcomp3.Backend.Cache.MP3LocalServer: java.lang.String currentUri> = "";
                            //
                            // TODO shall use the same method to handle instance fields across methods?
                            // Issue 51
                            //
                            bdg.addTaintValue("r0.<...>", real_mthd_sig);//Deal with removeTaintValue()
                            // [Solve issue #53] Use FLAG_STMT to handle the Return Var
                            backwardOneMethod(MyConstant.FLAG_STMT, real_mthd_sig, 
                                    invokebody, bdg, isStaticTrack, nextContainer);
                            
                            // 
                            // Taint base and parameters
                            // Has no problem to taint base again, because we use Set
                            //
                            // Fix issue 55: Not all parameters need to be tainted
                            //
                            Set<String> invokeset = bdg.getTaintSet(real_mthd_sig);
                            for (String invoketaint : invokeset) {
                                if (invoketaint.startsWith("@parameter")) {
                                    //TODO shall have no two digits
                                    // get "0" from "@parameter0"
                                    String paranum = String.format("%c", invoketaint.charAt(10));
                                    int paraindex = Integer.parseInt(paranum);
                                    Value para = ie.getArg(paraindex);
                                    bdg.addTaintValue(para, msig);
                                }
                            }
                            
                            innerCallChain.remove(innerCallChain.size() - 1);
                            MyUtil.printlnOutput(String.format("%s Back to the previous %s",
                                    MyConstant.BackPrefix, msig),
                                    MyConstant.WARN);
                            
                            //
                            // Add a return edge here
                            // And set it to be the last node
                            //
                            // TODO the above similar code also needs to be adjusted?
                            //
                            BDGUnit lastnode = bdg.getLastNode(isStaticTrack);
                            if (!lastnode.equals(node)) {
                                bdg.createSpecialBDGEdge(node, isStaticTrack);
                                bdg.setLastNode(node, isStaticTrack);
                            }
                        }
                    }
                }
                
            }//--end of InvokeStmt
            
            /**
             * Check methods contain static fields
             */
            if (!isThisStmtTainted && !isStaticTrack && !fieldset.isEmpty()) {
                String pre_unit_str = pre_unit.toString();
                Set<String> fieldfuncs = FieldWorker.v().generateFieldFuncs(fieldset);
                for (String fieldfuncmsg : fieldfuncs) {
                    if (pre_unit_str.contains(fieldfuncmsg)) {
                        MyUtil.printlnOutput(String.format("%s Catch a field method: %s",
                                MyConstant.NormalPrefix, fieldfuncmsg), MyConstant.DEBUG);
                        BDGUnit node = bdg.addNormalNode(pre_unit, msig, isReturn, isStaticTrack);
                        
                        /*
                         * Also backward slicing this function
                         */
                        InvokeExpr invokeexpr = 
                                MyUtil.extractInvokeExprFromUnit(pre_unit);
                        
                        if (invokeexpr == null) {
                            MyUtil.printlnOutput(String.format("%s Skipping a null field func: %s",
                                    MyConstant.ErrorPrefix, pre_unit_str.toString()),
                                    MyConstant.RELEASE);
                            cur_unit = pre_unit;
                            continue;
                        }
                        
                        //
                        // TODO retrieve the invoke method
                        // TODO Use call graph.  furtherCheck() uses this way
                        // TODO Or use soot method resolve?
                        //
                        SootMethod invokemethod = invokeexpr.getMethod();
                        
                        //
                        // Resolve the method body
                        // TODO Currently this way is not accurate, better to use points-to
                        //
                        Body invokebody = MyUtil.retrieveActiveSSABody(invokemethod);
                        if (invokebody == null) {
                            MyUtil.printlnOutput(String.format("%s Skipping a unresolvable field func: %s",
                                    MyConstant.ErrorPrefix, pre_unit_str.toString()),
                                    MyConstant.RELEASE);
                            cur_unit = pre_unit;
                            continue;
                        }
                        
                        // 
                        // Avoid the dead method loop
                        // Use the call chain to avoid more complicated method loop
                        //
                        String real_mthd_sig = invokemethod.getSignature();
                        if (innerCallChain.contains(real_mthd_sig)) {
                            MyUtil.printlnOutput(String.format("%s %s: %s",
                                    MyConstant.ErrorPrefix,
                                    MyConstant.DeadInner_Backward, real_mthd_sig),
                                    MyConstant.WARN);
                            MyUtil.printlnOutput(
                                    String.format("[DeadLoop]%s---%s---InnerBackward",
                                    PortDetector.PKGmust, msig), MyConstant.RELEASE);
                            cur_unit = pre_unit;
                            continue;
                        } else {
                            innerCallChain.add(real_mthd_sig);
                        }
                        
                        // [Solve issue #53] Use FLAG_STMT to handle the Return Var
                        backwardOneMethod(MyConstant.FLAG_STMT, real_mthd_sig,
                                invokebody, bdg, isStaticTrack, nextContainer);
                        
                        innerCallChain.remove(innerCallChain.size() - 1);
                        MyUtil.printlnOutput(String.format("%s Back to the previous %s",
                                MyConstant.BackPrefix, msig),
                                MyConstant.WARN);
                        
                        //
                        // Add a return edge here
                        // And set it to be the last node
                        //
                        bdg.createSpecialBDGEdge(node, isStaticTrack);
                        bdg.setLastNode(node, isStaticTrack);
                    }
                }
            }
            
            cur_unit = pre_unit;
            
        }//--end of loop
        
        
        /**
         * Perform inter-method backward slicing
         * 
         * Determine the parameter and whether keep forward
         * It should be different from the intra-method cross method
         */
        // First exclude the case of InvokeExpr, i.e., the intra-method cross method
        if (isFromInside)
            return;
        if (isStaticTrack) {
            // set the tail node
            BDGUnit endnode = bdg.getLastNode(isStaticTrack);
            bdg.setTailNode(endnode, isStaticTrack);
            return;
        }
        
        // 
        // Determine parameters
        // TODO Handle static fields later
        // TODO @this variable shall be always tainted? Because for a precise call graph
        //
        Set<String> oldset = bdg.getTaintSet(msig);
        Set<String> fieldset = bdg.getTaintSet(MyConstant.GLOBALFIELD);
        Set<String> newset = this.generateCrossParams(oldset);
        if (newset.isEmpty() && fieldset.isEmpty()) {
            // set the tail node
            if (false) {
                // TODO Enabled for ERP: whether we track to entry or not
                BDGUnit endnode = bdg.getLastNode(isStaticTrack);
                bdg.setTailNode(endnode, isStaticTrack);
                return;
            }
        }
        
        SootMethod method = body.getMethod();
        SootClass mclass = method.getDeclaringClass();
        
        crossCallerMethod(method, bdg, newset, isStaticTrack, null, nextContainer);
        
        if (false) {
            /*
             * Search over implicit flows
             * Special treatment to start() --> run()
             */
            if (msig.contains("void run()") || msig.contains("java.lang.Object call()")
                    || msig.contains("void onClick(android.view.View)")
                    || msig.contains("void onClick(android.content.DialogInterface,int)")
                    || msig.contains("void onItemClick(android.widget.AdapterView,android.view.View,int,long)")
                    || msig.contains("void onAnimationEnd(android.view.animation.Animation)")
                    || msig.contains("void onAnimationRepeat(android.view.animation.Animation)")
                    || msig.contains("void onAnimationStart(android.view.animation.Animation)")
                    || msig.contains("boolean onNavigationItemSelected(android.view.MenuItem)")
                    || msig.contains("void onCharacteristicRead(android.bluetooth.BluetoothGatt,android.bluetooth.BluetoothGattCharacteristic,int)")
                    || msig.contains("void onCharacteristicChanged(android.bluetooth.BluetoothGatt,android.bluetooth.BluetoothGattCharacteristic)")
                    || msig.contains("void onCharacteristicWrite(android.bluetooth.BluetoothGatt,android.bluetooth.BluetoothGattCharacteristic,int)")
                    || msig.contains("void onDescriptorRead(android.bluetooth.BluetoothGatt,android.bluetooth.BluetoothGattDescriptor,int)")
                    || msig.contains("void onDescriptorWrite(android.bluetooth.BluetoothGatt,android.bluetooth.BluetoothGattDescriptor,int)")
                    || msig.contains("void onConnectionStateChange(android.bluetooth.BluetoothGatt,int,int)")
                    || msig.contains("void onMtuChanged(android.bluetooth.BluetoothGatt,int,int)")
                    || msig.contains("void onReadRemoteRssi(android.bluetooth.BluetoothGatt,int,int)")
                    || msig.contains("void onReliableWriteCompleted(android.bluetooth.BluetoothGatt,int)")
                    || msig.contains("void onServicesDiscovered(android.bluetooth.BluetoothGatt,int)")
                    || msig.contains("void onLeScan(android.bluetooth.BluetoothDevice,int,byte[])")
                    || msig.contains("boolean onEditorAction(android.widget.TextView,int,android.view.KeyEvent)")
                    || msig.contains("boolean onTouch(android.view.View,android.view.MotionEvent)")
                    /*
                     * Quickly added on 180122
                     */
                    || msig.contains("android.support.v7.widget.RecyclerView$ViewHolder onCreateViewHolder(android.view.ViewGroup,int)")
                    || msig.contains("android.view.View onCreateView(android.view.ViewGroup)")
                    || msig.contains("boolean onActionItemClicked(android.support.v7.view.ActionMode,android.view.MenuItem)")
                    || msig.contains("boolean onCreateWindow(android.webkit.WebView,boolean,boolean,android.os.Message)")
                    || msig.contains("boolean onDragEvent(android.view.DragEvent)")
                    || msig.contains("boolean onError(android.media.MediaPlayer,int,int)")
                    || msig.contains("boolean onFling(android.view.MotionEvent,android.view.MotionEvent,float,float)")
                    || msig.contains("boolean onItemLongClick(android.widget.AdapterView,android.view.View,int,long)")
                    || msig.contains("boolean onKey(android.view.View,int,android.view.KeyEvent)")
                    || msig.contains("boolean onLongClick(android.view.View)")
                    || msig.contains("boolean onMenuItemClick(android.view.MenuItem)")
                    || msig.contains("boolean onMenuItemClick(com.actionbarsherlock.view.MenuItem)")
                    || msig.contains("boolean onPreferenceChange(android.preference.Preference,java.lang.Object)")
                    || msig.contains("boolean onPreferenceClick(android.preference.Preference)")
                    || msig.contains("boolean onSingleTapConfirmed(android.view.MotionEvent)")
                    || msig.contains("boolean onSurfaceTextureDestroyed(android.graphics.SurfaceTexture)")
                    || msig.contains("boolean onTouchEvent(android.view.MotionEvent)")
                    || msig.contains("void onActivityCreated(android.app.Activity,android.os.Bundle)")
                    || msig.contains("void onActivityDestroyed(android.app.Activity)")
                    || msig.contains("void onActivityResumed(android.app.Activity)")
                    || msig.contains("void onAnimationEnd(android.animation.Animator)")
                    || msig.contains("void onAudioFocusChange(int)")
                    || msig.contains("void onAvailable(android.net.Network)")
                    || msig.contains("void onBindViewHolder(android.support.v7.widget.RecyclerView$ViewHolder,int)")
                    || msig.contains("void onCallStateChanged(int,java.lang.String)")
                    /*
                     * The old last one
                     */
                    || msig.contains("onReceivedError(android.webkit.WebView,int,java.lang.String,java.lang.String)")) {
                boolean isRunCalled = false;
                CallerContainer one_caller = null;
                
                MyUtil.printlnOutput(String.format("%s Finding an implicit callback %s in backwardOneMethod",
                        MyConstant.CriticalPrefix, msig),
                        MyConstant.RELEASE);
                
                /*
                 * First check the calls in other classes
                 */
                List<SootMethod> initmethods = 
                        ClassWorker.getInstanceInitMethods(mclass);
                for (SootMethod initmethod : initmethods) {
                    // save it for switch to another path later
                    BDGUnit lastnode = bdg.getLastNode(isStaticTrack);
                    
                    // The previous version
//                  Set<String> fakeset = specialInitMethod(initmethod, bdg, isStaticTrack);
                    crossCallerMethod(initmethod, bdg, newset, isStaticTrack, method.makeRef(), nextContainer);
//                  findImplicitCaller(initmethod, bdg, isStaticTrack);
                    
                    // Check called
                    Set<CallerContainer> caller_methods = callerResCache.get(initmethod.getSignature());
                    if (!caller_methods.isEmpty())
                        isRunCalled = true;
                    
                    // For switching to another path
                    bdg.setLastNode(lastnode, isStaticTrack);
                }
                
                /*
                 * Then check the call in this class, see issue #69
                 * 
                 */
                if (!isRunCalled) {
                    Set<CallerContainer> caller_methods;
                    
                    // check the cache
                    if (callerResCache.containsKey(msig)) {
                        caller_methods = callerResCache.get(msig);
                    }
                    // find the this caller ourself
                    else {
                        caller_methods = ClassWorker.findThisStartCallers(mclass);
                        callerResCache.put(msig, caller_methods);
                    }
                    
                    // Currently we only use one caller
                    if (!caller_methods.isEmpty())
                        one_caller = caller_methods.iterator().next();//Originally is .get(0)
                    
                    /*
                     * Backward the caller
                     * Similar to the below
                     */
                    if (one_caller != null) {
                        SootMethod src_method = one_caller.getSrcMethod();
                        Unit src_unit = one_caller.getSrcUnit();
                        String src_msig = src_method.getSignature();
                        MyUtil.printlnOutput(String.format("%s Tracing %s at %s",
                                MyConstant.BackPrefix, src_msig, src_unit),
                                MyConstant.WARN);
                        
                        if (crossCallChain.contains(src_msig)) {
                            MyUtil.printlnOutput(String.format("%s Detect a dead loop for cross method: %s",
                                    MyConstant.ErrorPrefix, src_msig),
                                    MyConstant.WARN);
                            return;
                        } else {
                            // set node
                            InvokeExpr src_expr = UnitWorker.v().getInvokeExpr(src_unit);
                            bdg.addNormalNode(src_unit, src_msig, isStaticTrack);
                            
                            // set parameter
                            for (String newtaint : newset) {
                                if (newtaint.startsWith("@this")) {
                                    if (src_expr instanceof InstanceInvokeExpr) {
                                        InstanceInvokeExpr iie = (InstanceInvokeExpr)src_expr;
                                        Value base = iie.getBase();
                                        bdg.addTaintValue(base, src_msig);
                                    }
                                }
                                else if (newtaint.startsWith("@parameter")) {
                                    //TODO shall have no two digits
                                    // get "0" from "@parameter0"
                                    String paranum = String.format("%c", newtaint.charAt(10));
                                    int paraindex = Integer.parseInt(paranum);
                                    Value para = src_expr.getArg(paraindex);
                                    bdg.addTaintValue(para, src_msig);
                                }
                            }
                            
                            // real backward
                            crossCallChain.add(src_msig);
                            Body src_body = MyUtil.retrieveActiveSSABody(src_method);
                            backwardOneMethod(src_unit, src_msig, src_body, 
                                    bdg, isStaticTrack, nextContainer);
                        }
                    }
                }
                
                /*
                 * Set the tail node
                 */
                if (!isRunCalled && one_caller == null) {
                    // Issue #88
                    // No method comes to <com.appsilicious.wallpapers.cropimage.KMCropRotateAndSaveWallpaperActivity: void onClick(android.view.View)>
                    if (MyUtil.isEntryMethod(method)) {
                        // Live code, so set tail node
                        MyUtil.printlnOutput(String.format("%s Entry method comes to %s",
                                MyConstant.CriticalPrefix, msig),
                                MyConstant.RELEASE);
                        BDGUnit endnode = bdg.getLastNode(isStaticTrack);
                        bdg.setTailNode(endnode, isStaticTrack);
                        
                    } else {
                        MyUtil.printlnOutput(String.format("%s No method comes to %s",
                                MyConstant.ErrorPrefix, msig),
                                MyConstant.RELEASE);
                        BDGUnit endnode = bdg.getLastNode(isStaticTrack);
                        bdg.setFakeTail(endnode, isStaticTrack);
                    }
                    
                    return;
                }
            }
            /*
             * Normal treatment to perform inter-procedural analysis
             */
            else {
                crossCallerMethod(method, bdg, newset, isStaticTrack, null, nextContainer);
            }
        }
    }

    /**
     * Find the caller unit(s) and caller methods
     * 
     * @param method The callee method
     * @param bdg
     * @param newset The cross-method parameter set
     * @param isStaticTrack TODO it is always false
     * @param mref used for creating fake unit TODO could be deleted?
     */
    private void crossCallerMethod(SootMethod method, BDG bdg, final Set<String> newset,
            final boolean isStaticTrack, final SootMethodRef mref,
            final CallerContainer nextContainer) {
        /*
         * First check currentEntryNum
         */
        if (liveEntryMethods.size() >= MyConstant.MAX_LIVE_ENTRYR_NUM)
            return;
        if (deadEntryMethods.size() >= MyConstant.MAX_DEAD_ENTRYR_NUM)
            return;
        
        // save it for switch to another path later
        BDGUnit lastnode = bdg.getLastNode(isStaticTrack);
        
        Set<CallerContainer> caller_methods;
        String msig = method.getSignature();
        
        MyUtil.printlnOutput(String.format("%s Analyzing %s in crossCallerMethod",
                MyConstant.ForwardPrefix, msig),
                MyConstant.DEBUG);
        
        /*
         * Special handling for static initializers
         * <com.heyzap.internal.FileFetchClient: void <clinit>()>
         */
        if (method.isStaticInitializer()) { //msig.contains("void <clinit>()")
            String cls_name = method.getDeclaringClass().getName();
            boolean isReachable = MyUtil.judgeStaticInitializer(cls_name);
            
            if (isReachable) {
                BDGUnit endnode = bdg.getLastNode(isStaticTrack);
                bdg.setTailNode(endnode, isStaticTrack);
                
            } else {
                BDGUnit endnode = bdg.getLastNode(isStaticTrack);
                bdg.setFakeTail(endnode, isStaticTrack);
            }
            
            return;
        }
        
        /*
         * Check nextContainer first
         */
        if (nextContainer != null) {
            MyUtil.printlnOutput(String.format(
                    "%s Use nextContainer %s for %s in crossCallerMethod",
                    MyConstant.NormalPrefix, nextContainer.toString(), msig),
                    MyConstant.DEBUG);
            caller_methods = new HashSet<CallerContainer>();
            caller_methods.add(nextContainer);
            
        } else {
            /*
             * Check the cache
             */
            if (callerResCache.containsKey(msig)) {
                cachedMtdNum++;
                caller_methods = callerResCache.get(msig);
            }
            /*
             * No cache
             */
            else {
                //
                // Use dexdump to grep which class calls this method
                // For <init> functions, we can use the full representation for grep
                // Then load that class, and then build the call graph
                // Use call graph to resolve the method and that Unit
                // Transform the parameter, jump to source method, and do intra-procedural analysis again
                //
                Map<String, StringBuilder> search_methods = 
                        MyUtil.transformIntoSearchMethod(method, false);
                
                /*
                 * Directly find out the methods containing the call sites
                 * Instead of the classes in earlier version
                 */
                caller_methods = new HashSet<CallerContainer>();
                /*
                 * Store the method appear class list
                 * 
                 * The Java format of the following:
                 * Lcom/lge/app1/service/TVConnectionService$1;
                 * Lcom/lge/app1/service/TVConnectionService;
                 */
                List<String> mtd_appear_classes = null;
                
                for (final String search_soot : search_methods.keySet()) {
                    // Once the up level finds callers, we do not further search? Seems ok!
                    // We cannot skip child class, but we may skip interface.
                    if (!caller_methods.isEmpty()
                            && search_soot.startsWith(MyConstant.Search_IN)) {
                        MyUtil.printlnOutput(String.format("%s caller_methods filled some (%s) and skip: %s",
                                MyConstant.CriticalPrefix, caller_methods.iterator().next(), search_soot), MyConstant.DEBUG);
                        break;
                    }
                    
                    String search_soot_msig = search_soot;  // Search_IN will adjust
                    StringBuilder search_dexdump_sb = search_methods.get(search_soot);
                    String search_dexdump = MyUtil.sanitizeSS(search_dexdump_sb.toString());
                    String cmdcontent;
                    cmdcontent = String.format("cat %s " +
                            "| grep -e \"%s\" -e \".*:                                        |\\[.*\\] \" -e \"    #.* : (in L.*;)\" " +
                            "| grep -B 2 -e \"%s\" " +
                            "| grep -e \".*:                                        |\\[.*\\] \" -e \"    #.* : (in L.*;)\" ",
                            PortDetector.DEXDUMPlog, search_dexdump, search_dexdump);
                    
                    /**
                     * Real command search below, three types.
                     */
                    List<String> results;
                    /*
                     * 1. Handle the interface search
                     * 
                     * Also Handler.sendMessage(), AsyncTask execute(java.lang.Object[])
                     * This kind of implicit calls
                     */
                    if (search_soot.startsWith(MyConstant.Search_IN)) {
                        // No longer search the raw interface callers
                        search_soot_msig = search_soot.substring(MyConstant.Search_INAPP.length());
                        String raw_cls_name = method.getDeclaringClass().getName();
                        
                        List<CallerContainer> interface_callers = ForwardTainter.v()
                                .traceObjectMethod(raw_cls_name, msig, search_soot_msig);
                        
                        if (interface_callers != null && !interface_callers.isEmpty()) {
                            MyUtil.printlnOutput(String.format("%s Interface search catchs results for %s",
                                    MyConstant.NormalPrefix, method.getSignature()),
                                    MyConstant.DEBUG);
                            for (CallerContainer interface_caller : interface_callers) {
                                MyUtil.printlnOutput(String.format("%s find interface caller method: %s",
                                        MyConstant.NormalPrefix, interface_caller.getSrcMethod().getSignature()),
                                        MyConstant.DEBUG);
                                caller_methods.add(interface_caller);
                            }
                        } else {
                            MyUtil.printlnOutput(String.format("%s Interface search has no results for %s",
                                    MyConstant.CriticalPrefix, method.getSignature()),
                                    MyConstant.WARN);
                        }
                        
                        results = new ArrayList<String>();//Avoid null pointer exception
                    }
                    /*
                     * 2. Special handling for the search over IPC
                     * TODO more IPC method signature
                     */
                    else if (search_soot.equals(MyConstant.startService_SubSig)
                            || search_soot.equals(MyConstant.sendBroadcast_SubSig)
                            || search_soot.equals(MyConstant.startActivityForResult_SubSig)) {
                        // Search "const-class .*, Lcom/lge/app1/fota/HttpServerService;"
                        List<String> res1 = MyUtil.grepMethodResult(cmdcontent);
                        MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                                MyConstant.ForwardPrefix, cmdcontent), MyConstant.DEBUG);
                        
                        //
                        // Service, Receiver, Activity
                        //
                        String temp_search_subsig = null;
                        if (search_soot.equals(MyConstant.startService_SubSig))
                            temp_search_subsig = ".startService:(Landroid/content/Intent;)Landroid/content/ComponentName;";
                        else if (search_soot.equals(MyConstant.sendBroadcast_SubSig))
                            temp_search_subsig = ".sendBroadcast:(Landroid/content/Intent;)V";
                        else if (search_soot.equals(MyConstant.startActivityForResult_SubSig))
                            temp_search_subsig = ".startActivityForResult:(Landroid/content/Intent;I)V";
                        
                        // Search startService
                        cmdcontent = String.format("cat %s " +
                                "| grep -e \"%s\" -e \".*:                                        |\\[.*\\] \" -e \"    #.* : (in L.*;)\" " +
                                "| grep -B 2 -e \"%s\" " +
                                "| grep -e \".*:                                        |\\[.*\\] \"  -e \"    #.* : (in L.*;)\" ",
                                PortDetector.DEXDUMPlog, temp_search_subsig, temp_search_subsig);
                        MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                                MyConstant.ForwardPrefix, cmdcontent), MyConstant.DEBUG);
                        List<String> res2 = MyUtil.grepMethodResult(cmdcontent);
                        
                        // Merge the two results
                        results = new ArrayList<String>();
                        for (String one_result : res1) {
                            if (res2.contains(one_result))
                                results.add(one_result);
                        }
                        
                    }
                    /*
                     * 3. Normal search commands
                     */
                    else {
                        results = MyUtil.grepMethodResult(cmdcontent);
                        MyUtil.printlnOutput(String.format("%s grep cmd: %s",
                                MyConstant.ForwardPrefix, cmdcontent), MyConstant.DEBUG);
                    }
                    
                    /**
                     * Analyze search results
                     */
                    for (String one_method : results) {
                        // com.studiosol.palcomp3.Backend.Cache.SmartCacheMgr.initLocalServer:(Landroid/content/Context;)V
                        MyUtil.printlnOutput(String.format("%s find caller method: %s",
                                MyConstant.NormalPrefix, one_method), MyConstant.DEBUG);
                        
                        // <com.studiosol.palcomp3.Backend.Cache.SmartCacheMgr: void initLocalServer(android.content.Context)>
                        String caller_sootmsig = MyUtil.transformIntoSootMSig(one_method);
                        
                        /*
                         * Avoid the dead loop by the caller method itself
                         * E.g., <com.bsb.hike.ui.fragments.OfflineAnimationFragment: void a(java.lang.Boolean)>
                         */
                        if (caller_sootmsig.equals(msig))
                            continue;
                        
                        String[] temp_splits = caller_sootmsig.split(": ");
                        String caller_cname = temp_splits[0].substring(1);
                        String caller_subsig = temp_splits[1].substring(0, temp_splits[1].length()-1);
                        
                        SootClass caller_class = 
                                ClassWorker.loadClass(caller_cname);    //TODO optimize it
                        SootMethod caller_method = 
                                MyUtil.sootGetMethod(caller_class, caller_subsig);
                        if (caller_method == null)  //TODO because of the bug in sootGetMethod()
                            continue;
                        
                        List<Unit> caller_units = MyUtil.findCallerUnits(caller_method, search_soot_msig);
                        for (Unit caller_unit : caller_units) {
                            caller_methods.add(new CallerContainer(caller_unit, caller_method));
                        }
                    }
                }//--end of "for (final String search_soot : search_methods.keySet()) {"
                
                /*
                 * Add the cache
                 */
                uniqueMtdNum++;
                callerResCache.put(msig, caller_methods);
            }
        }
        
        // Print if no edge into the current method
        if (caller_methods.isEmpty()) {
            // set the tail node
            if (mref == null) {
                if (MyUtil.isEntryMethod(method)) {
                    // Live code, so set tail node
                    MyUtil.printlnOutput(String.format("%s Entry method comes to %s",
                            MyConstant.CriticalPrefix, msig),
                            MyConstant.WARN);
                    BDGUnit endnode = bdg.getLastNode(isStaticTrack);
                    bdg.setTailNode(endnode, isStaticTrack);
                    
                    isCurrentReachable = true;
                    liveEntryMethods.add(msig);
                    
                } else {
                    int debugLevel;
                    String mname = MyUtil.extractMethodFromMSig(msig);
                    if (mname.startsWith("on"))
                        debugLevel = MyConstant.WARN;   //TODO Release
                    else
                        debugLevel = MyConstant.WARN;
                    
                    // Dead code
                    MyUtil.printlnOutput(String.format("%s No method comes to %s",
                            MyConstant.CriticalPrefix, msig),
                            debugLevel);    //some apps output too much...
                    if (false)
                        MyUtil.printlnOutput(String.format("%s No method sbsig is %s",
                                MyConstant.CriticalPrefix, method.getSubSignature()),
                                debugLevel);
                    
                    BDGUnit endnode = bdg.getLastNode(isStaticTrack);
                    bdg.setFakeTail(endnode, isStaticTrack);
                    
                    deadEntryMethods.add(msig);
                }
            }
            
            if (false) {
                /*
                 * If there is still static field, we search its <clinit> function.
                 * 
                 * Otherwise, we set the tail node.
                 */
                Set<String> fieldset = bdg.getTaintSet(MyConstant.GLOBALFIELD);
                if (fieldset.isEmpty() || msig.contains("void <clinit>()>")) {
                    BDGUnit endnode = bdg.getLastNode(isStaticTrack);
                    bdg.setTailNode(endnode, isStaticTrack);
                    
                } else {
                    MyUtil.printlnOutput(String.format("%s Tracking a static func at %s",
                            MyConstant.ErrorPrefix, msig),
                            MyConstant.WARN);
                    
                    // Hard to avoid the over tracking for different static vars
                    Set<SootClass> sf_classes = bdg.getAllFieldClasses();
                    for (SootClass sf_class : sf_classes) {
                        if (sf_class != null) {
                            // save it for switch to another field class later
                            BDGUnit tempnode = bdg.getLastNode(isStaticTrack);
                            
                            specialStaticMethod(sf_class, bdg);
                            
                            // For switching to another field class
                            bdg.setLastNode(tempnode, isStaticTrack);
                        }
                    }
                }
            }
            
            return;
        }
        
        /*
         * real backward tracing
         */
//        int warn_caller_num = MyConstant.MAX_CALLER_NUM / 2;
//        if (caller_methods.size() >= warn_caller_num) {
//            MyUtil.printlnOutput(String.format(
//                    "%s crossCallerMethod finds %d+ caller methods for %s",
//                    MyConstant.CriticalPrefix, warn_caller_num, msig),
//                    MyConstant.WARN);
//        }
        
        int i = 0;
        for (CallerContainer one_caller : caller_methods) {
            // Prepare the src_msig for condition determination
            SootMethod src_method = one_caller.getSrcMethod();
            String src_msig = src_method.getSignature();
            
            /*
             * Use some signatures to avoid too much analysis
             * Probably could be removed after better interface search
             */
            if (false) {
            if (msig.startsWith(MyConstant.Facebook_SDK)) {
                if (src_msig.startsWith(MyConstant.Mopub_SDK)
                        || src_msig.startsWith(MyConstant.GoogleAd_SDK)
                        || src_msig.startsWith(MyConstant.Heyzap_SDK)
                        || src_msig.startsWith(MyConstant.Flurry_SDK)) {
                    MyUtil.printlnOutput(String.format("%s Skip libraries when analyzing Facebook SDK: %s",
                            MyConstant.ErrorPrefix, src_msig), MyConstant.RELEASE);
                    // TODO Do we need to set the tail node?
                    continue;
                }
            }
            }
            
            /*
             * Determine whether a dead cross-method loop.
             * TODO write into paper
             */
            if (crossCallChain.contains(src_msig)) {
                MyUtil.printlnOutput(String.format("%s %s: %s",
                        MyConstant.ErrorPrefix, MyConstant.DeadCross_Backward, src_msig),
                        MyConstant.WARN);
                MyUtil.printlnOutput(
                        String.format("[DeadLoop]%s---%s---CrossBackward",
                        PortDetector.PKGmust, msig), MyConstant.RELEASE);
                // TODO Do we need to set the tail node?
                // Just let it be, this path has issue anyway
                continue;
            }
            
            //
            // Avoid too much caller.
            // E.g., xcxin.filexpert-258_xcxin.filexpert.webserver.e_BDG
            // We limit each to MAX_CALLER_NUM callers
            //
            if (i >= MyConstant.MAX_CALLER_NUM) {
                MyUtil.printlnOutput(String.format("%s We limit to %d caller methods for %s.",
                        MyConstant.ErrorPrefix, MyConstant.MAX_CALLER_NUM, msig),
                        MyConstant.RELEASE);
                break;
            }
            i++;
            
            /*
             * Now we can do analysis
             */
            Unit src_unit = one_caller.getSrcUnit();
            MyUtil.printlnOutput(String.format("%s Tracing %s at %s",
                    MyConstant.BackPrefix, src_msig, src_unit),
                    MyConstant.WARN);
            
            /*
             * set the node
             * 
             * TODO Special handling for implicit flows
             */
            InvokeExpr src_expr = UnitWorker.v().getInvokeExpr(src_unit);
            if (mref == null) {
                bdg.addNormalNode(src_unit, src_msig, isStaticTrack);
                
            } else {
                InstanceInvokeExpr iie = (InstanceInvokeExpr)src_expr;
                Value base = iie.getBase();
                JVirtualInvokeExpr fakeie = new 
                        JVirtualInvokeExpr(base, mref, new ArrayList<Value>());
                JInvokeStmt fakeunit = new JInvokeStmt(fakeie);
                bdg.addNormalNode(fakeunit, src_msig, isStaticTrack);
            }
            
            /** 
             * set the cross-method taint set
             * This has no difference for both cases.
             */
            for (String newtaint : newset) {
                if (newtaint.startsWith("@this")) {
                    if (src_expr instanceof InstanceInvokeExpr) {
                        InstanceInvokeExpr iie = (InstanceInvokeExpr)src_expr;
                        Value base = iie.getBase();
                        bdg.addTaintValue(base, src_msig);
                    }
                }
                else if (newtaint.startsWith("@parameter")) {
                    //TODO shall have no two digits
                    // get "0" from "@parameter0"
                    String paranum = String.format("%c", newtaint.charAt(10));
                    int paraindex = Integer.parseInt(paranum);
                    try {
                        // Interface search could be nop, causing src_expr become null
                        if (src_expr != null) {
                            Value para = src_expr.getArg(paraindex);
                            bdg.addTaintValue(para, src_msig);
                        }
                        
                    } catch (ArrayIndexOutOfBoundsException e) {
                        MyUtil.printlnOutput(String.format("%s Detect an overlength parameter %d",
                                MyConstant.ErrorPrefix, paraindex),
                                MyConstant.RELEASE);
                    }
                }
            }
            
            /**
             * Invoke the backward
             * Also differentiate whether mref is null or not
             */
            CallerContainer next_caller = null;
            if (one_caller.hasNextContainer())
                next_caller = one_caller.getNextContainer();
            // Save the old index
            int last_idx = crossCallChain.size() - 1;
            crossCallChain.add(src_msig);
            // Get the body
            Body src_body = MyUtil.retrieveActiveSSABody(src_method);
            if (src_body != null) { //TODO is this way correct?
                if (mref == null) {
                    backwardOneMethod(src_unit, src_msig, src_body, 
                            bdg, isStaticTrack, next_caller);
                    
                } else {
                    Unit pre_unit = src_body.getUnits().getSuccOf(src_unit);
                    backwardOneMethod(pre_unit, src_msig, src_body, 
                            bdg, isStaticTrack, next_caller);
                }
            }
            
            // For switching to another caller
            crossCallChain.subList(last_idx+1, crossCallChain.size())
                          .clear();     //https://stackoverflow.com/a/10798153/197165
            bdg.setLastNode(lastnode, isStaticTrack);
        }
    }

    /**
     * Generate cross-method parameter set
     * - @this: com.afollestad.neuron.Terminal$1
     * - @parameter0: com.afollestad.neuron.Terminal
     * 
     * TODO Can be a static util function
     * 
     * @param oldset
     * @return Empty set if no cross-method parameters
     */
    private Set<String> generateCrossParams(Set<String> oldset) {
        Set<String> newset = new HashSet<String>();
        
        for (String oldtaint : oldset) {
            if (oldtaint.startsWith("@parameter")
                    || oldtaint.startsWith("@this")) {
                newset.add(oldtaint);
            }
        }
        
        return newset;
    }
    
    /**
     * Backward search the first return unit
     * 
     * TODO how to handle multiple return
     * 
     * @param u_chain
     * @return the last unit if no return unit is found
     */
    private Unit findReturnUnit(PatchingChain<Unit> u_chain) {
        Unit last_unit = u_chain.getLast();
        Value return_value;
        
        // If null
        if (last_unit == null)
            return null;
        
        // If the last is return, which should be the typical case
        return_value = MyUtil.extractReturnValueFromUnit(last_unit);
        if (return_value != null)
            return last_unit;
        
        // Loop other units
        Unit cur_unit, pre_unit;
        cur_unit = last_unit;
        while (true) {
            pre_unit = u_chain.getPredOf(cur_unit);
            if (pre_unit == null)
                break;
            
            return_value = MyUtil.extractReturnValueFromUnit(pre_unit);
            if (return_value != null)
                return pre_unit;
            
            cur_unit = pre_unit;
        }
        
        // Still not found
        return last_unit;
    }
    
    /**
     * Handle uninitialized static fields, but should not handle system class
     * 
     * @param bdg
     */
    private void finalHandleStaticFields(BDG bdg) {
        MyUtil.printlnOutput(String.format("%s Start to finalHandleStaticFields",
                MyConstant.ForwardPrefix),
                MyConstant.WARN);
        
        Set<String> visitedclasses = new HashSet<String>();
        
        while (true) {
            boolean isAnalyzed = false;
            
            // After a round, we need to check whether new SootClass to be analyzed
            Set<SootClass> sf_classes = bdg.getAllFieldClasses();
            for (SootClass sf_class : sf_classes) {
                if (sf_class != null) {
                    String str_class = sf_class.getName();
                    if (!visitedclasses.contains(str_class)
                            && !PortDetector.apiClassSet.contains(str_class)) {
                        specialStaticMethod(sf_class, bdg);
                        visitedclasses.add(sf_class.getName());
                        isAnalyzed = true;
                    }
                }
            }
            
            if (!isAnalyzed)
                break;
        }
    }
    
    /**
     * 
     * @param sf_class
     * @param bdg
     */
    private void specialStaticMethod(SootClass sf_class, BDG bdg) {
        SootMethod sf_clinit = ClassWorker.getOneStaticInitMethod(sf_class);
        
        if (sf_clinit != null) {
            MyUtil.printlnOutput(String.format("%s Tracking a static func for %s",
                    MyConstant.ForwardPrefix, sf_class.toString()),
                    MyConstant.WARN);
            
            Body sf_body = MyUtil.retrieveActiveSSABody(sf_clinit);
            if (sf_body == null)
                return;
            
            // last_unit is always "return;" for <clinit>
            Unit last_unit = sf_body.getUnits().getLast();
            bdg.addInitFieldNode(last_unit, sf_clinit.getSignature());
            
            backwardOneMethod(last_unit,
                    sf_clinit.getSignature(),
                    sf_body, bdg, true, null);
        }
    }
    
    /**
     * A special treatment:
     * Add all statements in InitMethod into BDG.
     * And return a fake cross-method parameter set. 
     * 
     * @param initmethod
     * @param bdg
     * @param isStaticTrack is always false
     * @return
     * 
     * @deprecated
     */
    private Set<String> specialInitMethod(SootMethod initmethod, BDG bdg,
            final boolean isStaticTrack) {
        Set<String> fakeset = new HashSet<String>();
        
        /*
         * Add all statements
         */
        String msig = initmethod.getSignature();
        Body body = MyUtil.retrieveActiveSSABody(initmethod);
        
        MyUtil.printlnOutput(String.format("%s specialInitMethod: %s",
                MyConstant.ForwardPrefix, msig), MyConstant.WARN);
        
        // TODO should have a CFG here
        PatchingChain<Unit> u_chain = body.getUnits();
        
        Unit cur_unit, pre_unit;
        cur_unit = u_chain.getLast();
        while (true) {
            pre_unit = u_chain.getPredOf(cur_unit);
            if (pre_unit == null)
                break;
            
            bdg.addNormalNode(pre_unit, msig, isStaticTrack);
            
            cur_unit = pre_unit;
        }
        
        /*
         * Generate fake cross-method parameter set
         */
        fakeset.add("@this");   //TODO necessary?
        int paranum = initmethod.getParameterCount();
        for (int i = 0; i < paranum; i++) {
            fakeset.add(String.format("@parameter%d", i));
        }
        
        return fakeset;
    }
    
    /**
     * Find the caller unit for the implicit flows
     * using the <init> method, and add the found unit into BDG
     * 
     * @param method The callee method
     * @param bdg
     * @param isStaticTrack TODO it is always false?
     * @deprecated
     */
    private void findImplicitCaller(SootMethod method, BDG bdg,
            final boolean isStaticTrack) {
        // save it for switch to another path later
        BDGUnit lastnode = bdg.getLastNode(isStaticTrack);
        
        //
        // Use dexdump to grep which class calls this method
        // For <init> functions, we can use the full representation for grep
        // Then load that class, and then build the call graph
        // Use call graph to resolve the method and that Unit
        // Transform the parameter, jump to source method, and do intra-procedural analysis again
        //
        List<StringBuilder> dexdump_method_sbs = 
                MyUtil.transformIntoDexDumpMethod(method);
        
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
                MyUtil.printlnOutput("--> loadClass: "+tempclass, MyConstant.DEBUG);
                // Add new class to call graph
                ClassWorker.loadClass(tempclass);
            }
        }
        
        CallGraph cg = ClassWorker.getCallGraph();
        
        // Calculate edges
        int edgelen = 0;
        Iterator<Edge> edges = cg.edgesInto(method);
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod src_method = edge.src();
            Unit src_unit = edge.srcUnit();
            String src_method_sig = src_method.getSignature();
            MyUtil.printlnOutput(String.format("%s Init Caller: %s at %s",
                    MyConstant.BackPrefix, src_method_sig, src_unit),
                    MyConstant.DEBUG);
            edgelen++;
        }
        
        // Print if no edge into the current method
        if (edgelen == 0) {
            String msig = method.getSignature();
            MyUtil.printlnOutput(String.format("%s No method comes to %s",
                    MyConstant.ErrorPrefix, msig), 
                    MyConstant.WARN);
            
            // set the tail node
            BDGUnit endnode = bdg.getLastNode(isStaticTrack);
            bdg.setTailNode(endnode, isStaticTrack);
            return;
        }
        
        /*
         * Do forward analysis to locate the real caller site
         */
        edges = cg.edgesInto(method);
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod src_method = edge.src();
            Unit src_unit = edge.srcUnit();
            String src_msig = src_method.getSignature();
            // "--> Forwarding specialinvoke $r12.<com.hike.transporter.c.b: 
            // void <init>(com.hike.transporter.b.a,com.hike.transporter.a.c)>(r1, $r13)
            // at ..."
            MyUtil.printlnOutput(String.format("%s Forwarding %s at %s",
                    MyConstant.ForwardPrefix, src_unit, src_msig),
                    MyConstant.DEBUG);
            
            if (!(src_unit instanceof SpecialInvokeExpr))
                continue;
            
            SpecialInvokeExpr src_ie = (SpecialInvokeExpr) src_unit;
        }
    }
    
    /**
     * TODO ideally, this should be in SSA representation
     * 
     * Backward parameter analysis starting from a Unit
     * 
     * This is a recursive method!
     * 
     * For those unit chain have already been constructed, we must invoke this method!
     * 
     * TODO:
     * 1) invokes:
     * -- $i1 = staticinvoke <java.lang.Math: int abs(int)>($i0);
     * -- $i0 = virtualinvoke $r0.<java.util.Random: int nextInt()>();
     * 2) polynomial:
     * -- $i3 = 8000 + $i2;
     * -- $i2 = $i1 % 1000;
     * 
     * @param unit
     * @param u_chain
     * @param track
     * @param tindex
     * @deprecated
     */
    public boolean backwardUnit(Unit unit, PatchingChain<Unit> u_chain, TrackContainer track, Value tindex) {
        boolean isTainted = false;
        
        /*
         * if unit is null, we assign the last unit
         */
        if (unit == null)
            unit = u_chain.getLast();
        
        /*
         * prepare for the potential split index
         */
        List<Value> tindexlist = new ArrayList<Value>();
        if (tindex != null) { //as the flag
            tindexlist.add(tindex);
        }
        
        /*
         * loop the previous units
         */
        Unit cur_unit, pre_unit;
        cur_unit = unit;
        while (true) {
            pre_unit = u_chain.getPredOf(cur_unit); //The last statement is basically "return", so no worry for not catching it
            if (pre_unit == null)
                break;

            /*
             * DefinitionStmt: $i0 = r0.<com.kugou.android.dlna.d.b.a: int c>;
             * AssignStmt belongs to DefinitionStmt: r0.<com.kugou.android.dlna.d.b.a: int c> = i0
             * 
             * $i3 = 8000 + $i2;
             */
            if (pre_unit instanceof DefinitionStmt) {
                DefinitionStmt ds = (DefinitionStmt) pre_unit;
                Value ds_left = ds.getLeftOp();

                List<ParaContainer> containers = track.getParaContainers();
                for (ParaContainer container : containers) {

                    List<TaintContainer> tclist = container.getCurrentTaints();
                    if (tclist == null)
                        continue;
                    
                    if (tindex != null)
                        MyUtil.printlnOutput(String.format("tindexlist: %s", tindexlist), MyConstant.INFO);
                    
                    for (TaintContainer tc : tclist) {
                        if (tindex != null) {
                            if (!tindexlist.contains(tc.getIndex()))
                                continue;
                        }
                        
                        Value tc_taint = tc.getTaint();
                        if (ds_left.toString().equals(tc_taint.toString())) {
                            Value ds_right = ds.getRightOp();
                            
                            /*
                             * should do method summary here!!!
                             * 
                             * -- $i0 = staticinvoke <com.kugou.framework.e.b.b.a: int c()>();
                             * 
                             * -- $i1 = staticinvoke <com.afollestad.neuron.Terminal: int access$000(com.afollestad.neuron.Terminal)>($r5);
                             *    We shall build a relationship between $i1 and $r5
                             */
                            if (ds_right instanceof InvokeExpr) {
                                MyUtil.printlnOutput("--> Recording one InvokeExpr: "+ds_right,
                                        MyConstant.DEBUG);
                                
                                UnitWorker.v().addOneExpr(ds_right, pre_unit);
                            }
                            
                            List<Value> templist = container.addTaintValue(tc.getIndex(), ds_right, null);
                            isTainted = true;
                            
                            // update tindexlist
                            if (tindex != null && !templist.isEmpty())
                                tindexlist = templist;
                        }
                    }
                }
            }
            /*
             * Only the function invocation, different from DefinitionStmt
             * 
             * specialinvoke $r8.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>($r9, $i0);
             * 
             * $r8 = new java.net.InetSocketAddress;
             * $r9 = r0.<hu.tagsoft.ttorrent.webserver.a.j: java.lang.String a>;
             * $i0 = r0.<hu.tagsoft.ttorrent.webserver.a.j: int b>;
             * specialinvoke $r8.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>($r9, $i0);
             * r3 = $r8;
             * 
             * TRUE{{specialinvoke r3.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>("127.0.0.1", @parameter0: int + 0)}}
             */
            else if (pre_unit instanceof InvokeStmt) {
                if (pre_unit.toString().contains("<init>")) {//TODO we only handle "new Class()"
                    InvokeStmt is = (InvokeStmt) pre_unit;
                    InvokeExpr ie = is.getInvokeExpr();
                    
                    if (ie instanceof InstanceInvokeExpr) {
                        InstanceInvokeExpr iie = (InstanceInvokeExpr)ie;
                        Value base = iie.getBase();
                        
                        List<ParaContainer> containers = track.getParaContainers();
                        for (ParaContainer container : containers) {
                            
                            List<TaintContainer> tclist = container.getCurrentTaints();
                            if (tclist == null)
                                continue;
                            
                            for (TaintContainer tc : tclist) {
                                if (tindex != null) {
                                    if (!tindexlist.contains(tc.getIndex()))
                                        continue;
                                }
                                
                                Value tc_taint = tc.getTaint();
                                if (base.toString().equals(tc_taint.toString())) {
                                    List<Value> templist = container.addTaintValue(tc.getIndex(), iie, null);
                                    isTainted = true;
                                    
                                    // update tindexlist
                                    if (tindex != null && !templist.isEmpty())
                                        tindexlist = templist;
                                }
                            }
                        }
                    }
                }
            }

            cur_unit = pre_unit;
        }
        
        return isTainted;
    }
    
    /**
     * For those unit chain have not been constructed, we can invoke this method
     * 
     * @param unit
     * @param method
     * @param track
     * @param tindex
     * @deprecated
     */
    public boolean backwardUnit(Unit unit, SootMethod method, TrackContainer track, Value tindex) {
        /*
         * get the unit chain
         * Previously We cannot use Shimple, otherwise, call graph causes NoSuchElementException
         */
        Body body = MyUtil.retrieveActiveSSABody(method);
        PatchingChain<Unit> u_chain = body.getUnits();
        
        return this.backwardUnit(unit, u_chain, track, tindex);
    }
    
}
