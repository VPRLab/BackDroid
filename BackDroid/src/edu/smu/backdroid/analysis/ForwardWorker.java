package edu.smu.backdroid.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import edu.smu.backdroid.PortDetector;
import edu.smu.backdroid.graph.BDG;
import edu.smu.backdroid.graph.BDGEdge;
import edu.smu.backdroid.graph.BDGEdgeType;
import edu.smu.backdroid.graph.BDGUnit;
import edu.smu.backdroid.structure.ArrayObj;
import edu.smu.backdroid.structure.InstanceObj;
import edu.smu.backdroid.structure.ResultContainer;
import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;
import soot.Body;
import soot.PatchingChain;
import soot.SootClass;
import soot.SootField;
import soot.SootFieldRef;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.ArrayRef;
import soot.jimple.BinopExpr;
import soot.jimple.CastExpr;
import soot.jimple.Constant;
import soot.jimple.DefinitionStmt;
import soot.jimple.InstanceFieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.NewArrayExpr;
import soot.jimple.NewExpr;
import soot.jimple.StaticFieldRef;
import soot.shimple.PhiExpr;
import soot.toolkits.scalar.ValueUnitPair;

/**
 * The main worker for forward analysis
 * 
 * @author Daoyuan
 * @since 17-06-15
 */
public class ForwardWorker {
    
    private static final String RETURN_KEY = "@return";
    
    private static final String THIS_KEY = "@this";
    
    private static final String INIT_KEY = "<init>";
    
    private BDG bdg;
    
    private Map<String, Object> fieldFacts;
    
    /**
     * Cache those analyzed classes for tag names
     */
    private static Map<String, String> classTagMap;
    
    /**
     * Cache those analyzed method signatures
     */
    private static Map<String, String> msigMarkMap;
    
    static {
        classTagMap = new HashMap<String, String>();
        msigMarkMap = new HashMap<String, String>();
    }
    
    public ForwardWorker(BDG bdg) {
        this.bdg = bdg;
        this.fieldFacts = new HashMap<String, Object>();
    }
    
    /**
     * The main function for analyzing a BDG
     * 
     * TODO Shall have a result return
     */
    public void analyzeBDG() {
        MyUtil.printlnOutput(String.format("%s analyzeBDG: %s",
                MyConstant.CriticalPrefix, bdg.getInitSig()),
                MyConstant.WARN);
        
        /*
         * Loop each field <clinit> function from the last.
         * 
         * Because one field may connect to another field.
         * 
         * Save all facts in one this.fieldFacts.
         */
        List<BDGUnit> fieldtails = bdg.getFieldTails();
        int i = fieldtails.size() - 1;
        for (; i >= 0; i--) {
            BDGUnit fieldtail = fieldtails.get(i);
            
            MyUtil.printlnOutput(String.format("%s Analyze fieldtail: %s",
                    MyConstant.ForwardPrefix, fieldtail.getMSig()),
                    MyConstant.DEBUG);
            
            // Save visited cross edges for now
            Set<BDGEdge> visitededges = new HashSet<BDGEdge>();
            
            // Start the analysis
            forwardEachNode(fieldtail, fieldFacts, visitededges, true, false, null);
        }
        
        /*
         * Start from each tail node
         */
        Set<BDGUnit> tailnodes = bdg.getNormalTails();
        for (BDGUnit tailnode : tailnodes) {
            MyUtil.printlnOutput(String.format("%s Analyze tailnode: %s",
                    MyConstant.ForwardPrefix, tailnode.getUnit().toString()),
                    MyConstant.DEBUG);
            
            /*
             * Create a FactMap and a PointsToMap for each path
             * 
             * FactMap is in this format:
             * - "@parameter1"  --> 1223
             * - "i0"           --> "@parameter1"   --> 1223
             * 
             * Change from Map<String, Value> to Map<String, String>
             * Further change to Map<String, Object>
             * Object can be either String or InstanceObj
             * 
             * TODO One tail node may have several different paths.
             * TODO Facts need to copy itself when going to multiple NORMAL edges.
             * 
             * Now because we add NODE_ID, each tail node will usually have one path.
             * So facts along different paths can be separated.
             */
            Map<String, Object> factmap = new HashMap<String, Object>();
            
            // Save visited cross edges for now
            Set<BDGEdge> visitededges = new HashSet<BDGEdge>();
            
            // Start the analysis
            List<String> markMSigList = new ArrayList<String>();
            markMSigList.add(tailnode.getMSig());
            forwardEachNode(tailnode, factmap, visitededges, false, false, markMSigList);
        }
        
        /*
         * TODO can setup an option here to continue analysis or not
         */
        if (false) {
            Set<BDGUnit> faketails = bdg.getFakeTails();
            for (BDGUnit failtail : faketails) {
                MyUtil.printlnOutput(String.format("%s Analyze failtail: %s",
                        MyConstant.ForwardPrefix, failtail.getUnit().toString()),
                        MyConstant.DEBUG);
                
                Map<String, Object> factmap = new HashMap<String, Object>();
                
                // Save visited cross edges for now
                Set<BDGEdge> visitededges = new HashSet<BDGEdge>();
                
                // Start the analysis
                List<String> markMSigList = new ArrayList<String>();
                markMSigList.add(failtail.getMSig());
                forwardEachNode(failtail, factmap, visitededges, false, true, markMSigList);
            }
        }
        
    }
    
    /**
     * Forward each node recursively
     * And propagate the facts along the way
     * 
     * @param node
     * @param factmap
     * @param visitededges
     */
    private void forwardEachNode(BDGUnit node,
            Map<String, Object> factmap, Set<BDGEdge> visitededges,
            final boolean isStaticTrack, final boolean isFakeTrack,
            List<String> markMSigList) {
        MyUtil.printlnOutput(String.format("%s forwardEachNode: %s",
                MyConstant.NormalPrefix, node.getUnit().toString()),
                MyConstant.DEBUG);
        
        String msig = node.getMSig();
        
        /*
         * Whether it has come to the init node
         */
        if (node.equals(bdg.getInitNode())) {
            // InvokeExpr here would not be null
            InvokeExpr ie = MyUtil.extractInvokeExprFromUnit(node.getUnit());
            
            /*
             * Output parameters into one string
             */
            StringBuilder sb = new StringBuilder();
            List<Value> params = ie.getArgs();
            int paramsize = params.size();
            boolean isBreak = false;
            
            for (Value param : params) {
                Object aftervalue = getConstantFromValueAndMap(param, factmap);
                if (aftervalue == null) {
                    isBreak = true;
                    break;
                } else {
                    sb.append(aftervalue.toString());
                    if (paramsize > 1) {
                        sb.append(",,");
                        paramsize--;
                    }
                }
            }
            
            if (isBreak) {
                MyUtil.printlnOutput(String.format("%s FINAL Param: Not resolvable",
                        MyConstant.CriticalPrefix),
                        MyConstant.WARN);
            } else {
                MyUtil.printlnOutput(String.format("%s FINAL Param: %s",
                        MyConstant.CriticalPrefix, sb.toString()),
                        MyConstant.WARN);
                
                /**
                 * Generate result!
                 */
                ResultContainer rescon = new ResultContainer();
                
                rescon.setMSig(bdg.getInitSig());
                rescon.setParams(sb.toString());
                
                String initmsig = bdg.getInitNode().getMSig();
                String initcname = MyUtil.extractFullClassFromMSig(initmsig);
                rescon.setInitMSig(initcname);
                
                if (isFakeTrack)
                    rescon.setLive(false);
                else
                    rescon.setLive(true);
                
                String tailmsig = markMSigList.get(0);
                String tailcname = MyUtil.extractFullClassFromMSig(tailmsig);
                rescon.setTailMSig(tailcname);
                
                // TODO set an option to record TAG or not
//                String tagname = findTagName(initcname);
//                if (tagname.equals(MyConstant.NO_TAG))
//                    tagname = "NOTAG";
//                rescon.setTailMSig(tagname);
                
                // TODO old version to extract all TAGs
//                StringBuilder marksb = new StringBuilder();
//                Set<String> markset = new HashSet<String>();
//                
//                // Init node
//                String initmark = extractMarkName(initmsig);
//                marksb.append(initmark);
//                markset.add(initmark);
//                
//                // Other nodes
//                if (markMSigList != null) {
//                    for (String markmsig : markMSigList) {
//                        String tempmark = extractMarkName(markmsig);
//                        if (!tempmark.isEmpty()) {
//                            markset.add(tempmark);
//                        }
//                    }
//                }
//                
//                // Set the mark name
//                for (String onemark : markset) {
//                    if (!onemark.equals(initmark)) {
//                        marksb.append(";");
//                        marksb.append(onemark);
//                    }
//                }
//                rescon.setMarkName(marksb.toString());
                
                // TODO set an option to record CLICK or not
                if (markMSigList.size() > 1)
                    rescon.setMarkName("onClick");
                else
                    rescon.setMarkName("NOCLICK");
                
                PortDetector.ResultSet.add(rescon);
                if (false)
                    PortDetector.printOneResult(rescon);
            }
            
            return;
        }
        
        /*
         * Get all outgoing edges
         */
        List<BDGEdge> edges = bdg.getOutgoingEdge(node, isStaticTrack);
        
        /*
         * 1. We analyze the internal loop, if one node has.
         * 
         * TODO Only the first?
         * Get (the first) cross edge and compute its facts
         * We need to first analyze the cross edge and then normal edge
         * 
         * We do not generate facts for this node yet, but only mark parameters
         * 
         * The rest is normal or return edge
         */
        BDGEdge crossedge = MyUtil.extractANDremoveCrossEdge(edges);
        if (crossedge != null && !visitededges.contains(crossedge)) {
            //
            // Mark it is been visited
            // To avoid the dead loop
            //
            visitededges.add(crossedge);
            
            /*
             * Determine whether add msig into the set
             * For other non-init nodes
             * 
             * For efficiency, we only need to do this in the CROSS_EDGE.
             * InitNode can be handled separately.
             * But field set will be missed.
             * 
             * If already in the set, then no need to analyze it again.
             */
            // TODO old version
//            if (markMSigList != null && !markMSigList.contains(msig)) {
//                String cname = MyUtil.extractClassNameFromMSig(msig);
//                String mname = MyUtil.extractMethodFromMSig(msig);
//                if (MyUtil.containsIgnoreCase(cname, "Server")
//                        || MyUtil.containsIgnoreCase(mname, "Server")) {
//                    markMSigList.add(msig);
//                }
//            }
            // TODO set an option to record CLICK or not
            if (msig.contains("void on") && msig.contains("Click(")) {
                markMSigList.add(msig);
            }
            
            //
            // Set up the parameters and @this
            //
            InvokeExpr ie = MyUtil.extractInvokeExprFromUnit(node.getUnit());
            if (ie != null) {
                // Parameters
                List<Value> params = ie.getArgs();
                SootMethod ie_method = ie.getMethod();
                for (int i = 0; i < params.size(); i++) {
                    Value param = params.get(i);
                    Type paramtype = ie_method.getParameterType(i);
                    Object aftervalue = getConstantFromValueAndMap(param, factmap);
                    if (aftervalue != null) {
                        String factkey = String.format("@parameter%d: %s",
                                i, paramtype.toString());   //TODO getEscapedName()
                        factmap.put(factkey, aftervalue);
                        MyUtil.printlnOutput(String.format("%s putIntoFactMap: %s --> %s",
                                MyConstant.NormalPrefix, factkey, aftervalue),
                                MyConstant.DEBUG);
                    }
                }
                
                // @this
                if (ie instanceof InstanceInvokeExpr) {
                    InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                    Value base = iie.getBase();
                    Object aftervalue = getConstantFromValueAndMap(base, factmap);
                    if (aftervalue != null) {
                        factmap.put(THIS_KEY, aftervalue);
                    }
                }
            }
            
            //
            // A cycle of facts will be generated here.
            // Then we just proceed to normal edge
            //
            BDGUnit crossnode = crossedge.getTarget();
            MyUtil.printlnOutput(String.format("%s Cross to method: %s",
                    MyConstant.ForwardPrefix, crossnode.getMSig()),
                    MyConstant.DEBUG);
            forwardEachNode(crossnode, factmap, visitededges, 
                    isStaticTrack, isFakeTrack, markMSigList);
        }
        
        // TODO Clear the previous parameters here?
        
        /*
         * If no next node: e.g., for cross node
         * And for the init nodes for field set.
         */
        if (edges.isEmpty())
            return;
        
        /*
         * 2. Analyze the current node.
         * Generate new facts for this statement/node.
         */
        flowEachStmt(node, factmap);
        
        /*
         * 3. Jump to next node for further analysis.
         * 
         * Propagate the facts to each other normal edge, if any.
         * Each path shall have one separated fact set.
         * 
         * TODO Do we later use the path #ID? For com.afollestad.neuron.Terminal$1_BDG
         */
        for (BDGEdge normaledge : edges) {
            //
            // Need to stop for return edge.
            // Otherwise, double the analysis
            //
            // Also no need for self-loop edge; otherwise, dead loop.
            //
            int edgetype = normaledge.getType();
            if (edgetype == BDGEdgeType.RETURN_EDGE
                    || edgetype == BDGEdgeType.SELFLOOP_EDGE
                    || edgetype == BDGEdgeType.UNKNOWN_EDGE)
                break;
            
            // Real normal edge
            BDGUnit nextnode = normaledge.getTarget();
            forwardEachNode(nextnode, factmap, visitededges, 
                    isStaticTrack, isFakeTrack, markMSigList);
        }
    }

    /**
     * This is a flow function for each node statement.
     * Generate new facts for this statement/node.
     * 
     * @param node
     * @param factmap
     */
    private void flowEachStmt(BDGUnit node, 
            Map<String, Object> factmap) {
        Unit unit = node.getUnit();
        if (unit == null)
            return;
        
        if (unit instanceof DefinitionStmt) {
            DefinitionStmt ds = (DefinitionStmt) unit;
            Value ds_left = ds.getLeftOp();
            Value ds_right = ds.getRightOp();
            
            /*
             * Handle the last return:
             * $i0 = staticinvoke <com.kugou.framework.e.b.b.a: int c()>();
             * 
             * TODO But the return may not be a DefinitionStmt.
             * TODO We need to clear it in the outside
             */
            if (factmap.containsKey(RETURN_KEY)) {
                Object returnvalue = factmap.get(RETURN_KEY);
                if (returnvalue != null)    //Maybe null if @return is unresolvable
                    factmap.put(ds_left.toString(), returnvalue);
                factmap.remove(RETURN_KEY); //Clear the @return
                
            } else {
                if (ds_right.toString().startsWith(THIS_KEY)) {
                    Object thisvalue = factmap.get(THIS_KEY);
                    factmap.put(ds_left.toString(), thisvalue);//TODO what if @this is null
                    factmap.remove(THIS_KEY);  //Clear the @this
                    
                } else {
                    Object aftervalue = flowEachExpr(ds_right, factmap);
                    if (aftervalue != null) {
                        /*
                         * Instance field:
                         * r0.<com.kugou.android.dlna.a.c: com.kugou.android.dlna.d.b.a f> = $r43
                         */
                        if (ds_left instanceof InstanceFieldRef) {
                            InstanceFieldRef ifr = (InstanceFieldRef) ds_left;
                            Value base = ifr.getBase();
                            Object basevalue = factmap.get(base.toString());
                            if (basevalue instanceof InstanceObj) {
                                SootField sf = ifr.getField();
                                String str_sf = sf.getSignature();
                                InstanceObj insobj = (InstanceObj) basevalue;
                                insobj.putOneFieldValue(str_sf, aftervalue);
                            } else {    //Simply value replacement
                                factmap.put(ds_left.toString(), aftervalue);
                            }
                        }
                        /*
                         * Array index:
                         * $r0[0] = 2609
                         */
                        else if (ds_left instanceof ArrayRef) {
                            ArrayRef ar = (ArrayRef) ds_left;
                            Value base = ar.getBase();
                            Object basevalue = factmap.get(base.toString());
                            boolean isArrObj = false;
                            // Exist such array obj
                            if (basevalue instanceof ArrayObj) {
                                Value index = ar.getIndex();
                                Object indexvalue = 
                                        getConstantFromValueAndMap(index, factmap);
                                // Index is also resolvable
                                if (indexvalue instanceof String) { //TODO should be int idealy
                                    ArrayObj arrayobj = (ArrayObj) basevalue;
                                    arrayobj.putOneIndexValue(
                                            indexvalue.toString(),
                                            aftervalue);
                                    isArrObj = true;
                                }
                            }
                            // Otherwise, simply value replacement. Suppose "new array" is not tracked.
                            if (!isArrObj) {
                                factmap.put(ds_left.toString(), aftervalue);
                            }
                        }
                        /*
                         * normal case
                         */
                        else {
                            factmap.put(ds_left.toString(), aftervalue);
                        }
                    }
                }
            }
        }
        /*
         * TODO Need modeling not only the <init> cases
         * Other InvokeStmt should be covered by forwardEachNode's cross-method analysis
         * 
         * specialinvoke $r8.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>($r9, $i0);
         * virtualinvoke r30.<android.content.Intent: android.content.Intent putExtra(java.lang.String,int)>($r14, 18888)
         */
        else if (unit instanceof InvokeStmt) {
            String unit_str = unit.toString();
            /*
             * Directly model the Intent class without calling flowEachExpr()
             */
            if (unit_str.contains("<android.content.Intent: ")
                    || unit_str.contains("<android.os.Bundle: ")) {
                // Retrieve the Intent InstanceObj
                InvokeExpr ie = MyUtil.extractInvokeExprFromUnit(unit);
                InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                Value base = iie.getBase();
                String str_base = base.toString();
                Object obj = factmap.get(str_base);
                
                if (obj instanceof InstanceObj) {
                    InstanceObj insobj = (InstanceObj) obj;
                    List<Value> argus = ie.getArgs();
                    
                    /*
                     * specialinvoke $r11.<android.content.Intent: void <init>(android.content.Context,java.lang.Class)>($r12, class "com/lge/app1/fota/HttpServerService")
                     */
                    if (unit_str.contains("<android.content.Intent: void <init>(android.content.Context,java.lang.Class)>")) {
                        insobj.putOneFieldValue("TARGET_INTENT_CLASS", argus.get(1).toString());//TODO toString or not
                    }
                    /*
                     * virtualinvoke r30.<android.content.Intent: android.content.Intent putExtra(java.lang.String,int)>($r14, 18888)
                     */
                    else if (unit_str.contains("<android.content.Intent: android.content.Intent putExtra(java.lang.String,int)>")) {
                        insobj.putOneFieldValue(
                                getConstantFromValueAndMap(argus.get(0), factmap).toString(),
                                getConstantFromValueAndMap(argus.get(1), factmap));
                    }
                    /*
                     * virtualinvoke r29.<android.os.Bundle: void putInt(java.lang.String,int)>("profile_id", i3)
                     */
                    else if (unit_str.contains("<android.os.Bundle: void putInt(java.lang.String,int)>")) {
                        insobj.putOneFieldValue(
                                getConstantFromValueAndMap(argus.get(0), factmap).toString(),
                                getConstantFromValueAndMap(argus.get(1), factmap));
                    }
                    /*
                     * virtualinvoke r28.<android.content.Intent: android.content.Intent putExtras(android.os.Bundle)>(r29)
                     */
                    else if (unit_str.contains("<android.content.Intent: android.content.Intent putExtras(android.os.Bundle)>")) {
                        Object argu = getConstantFromValueAndMap(argus.get(0), factmap);
                        if (argu instanceof InstanceObj) {
                            InstanceObj argu_insobj = (InstanceObj) argu;
                            Map<String, Object> argu1_objfields = argu_insobj.getObjFields();
                            for (String argu_key : argu1_objfields.keySet()) {
                                insobj.putOneFieldValue(argu_key, 
                                        argu_insobj.getOneFieldValue(argu_key));
                            }
                        }
                    }
                }
            }
            /*
             * Handle other <init> methods
             */
            else if (unit_str.contains(INIT_KEY)) {
                InvokeExpr ie = MyUtil.extractInvokeExprFromUnit(unit);
                InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                Value base = iie.getBase();
                String str_base = base.toString();
                
                Object obj = factmap.get(str_base);
                SootMethod ie_method = ie.getMethod();
                String str_class = ie_method.getDeclaringClass().getName();
                
                if (PortDetector.apiClassSet.contains(str_class)
                        || obj == null
                        || !(obj instanceof InstanceObj)) {
                    Object afterbase = flowEachExpr(ie, factmap);
                    if (afterbase != null)
                        factmap.put(str_base, afterbase);
                }
                /*
                 * Fix issue #52
                 */
//                else {
//                    InstanceObj insobj = (InstanceObj) obj;
//                    SootClass obj_class = insobj.getObjClass();
//                    String submsig = ie_method.getSubSignature();
//                    SootMethod obj_method = MyUtil.findInstanceInitMethod(
//                            obj_class, submsig);    //More accurate than ie_method
//                    
//                    // Set up the parameters
//                    List<Value> params = ie.getArgs();
//                    for (int i = 0; i < params.size(); i++) {
//                        Value param = params.get(i);
//                        Type paramtype = ie_method.getParameterType(i);
//                        Object aftervalue = getConstantFromValueAndMap(param, factmap);
//                        if (aftervalue != null) {
//                            factmap.put(String.format("@parameter%d: %s",
//                                    i, paramtype.toString()), aftervalue);  //TODO getEscapedName()
//                        }
//                    }
//                    
//                    // Jump to <init> to analyze
//                    markInitMethod(insobj, obj_method, factmap);
//                }
            }
        }
        /*
         * Return statements: return $i0
         * and
         * Some other nodes introduced by specialInitMethod()
         */
        else {
            // TODO Only handle return: $i0
            Value returnvalue = MyUtil.extractReturnValueFromUnit(unit);
            if (returnvalue != null) {
                Object aftervalue = flowEachExpr(returnvalue, factmap);
                // Set a real @return value
                if (aftervalue != null) {
                    factmap.put(RETURN_KEY, aftervalue);
                    MyUtil.printlnOutput(String.format("%s Set return: %s",
                            MyConstant.NormalPrefix, aftervalue),
                            MyConstant.DEBUG);
                }
                // Also set @return as null
                else {
                    factmap.put(RETURN_KEY, null);
                    MyUtil.printlnOutput(String.format("%s Set return: null",
                            MyConstant.NormalPrefix),
                            MyConstant.DEBUG);
                }
            }
        }
    }

    /**
     * A key function to handle different kinds of Expr.
     * Similar to BDG.addTaintValue()
     * 
     * DefinitionStmt:
     * $i0 = r0.<com.kugou.android.dlna.d.b.a: int c>;  //TODO need replace r0
     * r0.<com.kugou.android.dlna.d.b.a: int c> = i0
     * $i3 = 8000 + $i2;
     * $i0 = (java.net.InetAddress) $r56
     * $r7 = new xcxin.filexpert.settings.i
     * 
     * @param value
     * @param factmap
     * @return null if the result should not be added into factmap
     * @see BDG
     * @see ParaContainer.transformResult
     */
    private Object flowEachExpr(Value value,
            Map<String, Object> factmap) {
        if (value == null)
            return null;
        
        Object result = null;
        
        //
        // First simplify CastExpr
        // -- CastExpr: (java.net.InetAddress) $r56, Op: $r56
        //
        if (value instanceof CastExpr) {
            CastExpr ce = (CastExpr)value;
            value = ce.getOp();
        }
        
        /**
         * Do the real translation
         */
        /*
         * TODO here the result of InvokeExpr will be only String
         */
        if (value instanceof InvokeExpr) {
            InvokeExpr ie = (InvokeExpr)value;
            String ie_str = ie.toString();      //TODO Is string here ok?
            
            //
            // Shall be able to handle partial base and parameters
            // Currently we require all parameters to be resolved
            //
//            boolean hasNull = false;
            
            // TODO Better handle the base variable
            Object afterbase = null;
            if (ie instanceof InstanceInvokeExpr) {
                InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                Value base = iie.getBase();
                afterbase = getConstantFromValueAndMap(base, factmap);
                if (afterbase != null) {
                    ie_str = ie_str.replace(base.toString(), 
                            afterbase.toString());//TODO string replace is not perfect
                } else {
                    /*
                     * $r10.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>($r11, $i1)
                     * where $r10 is not resolvable
                     * so we replace "$r10." with empty string
                     */
                    if (ie_str.contains(INIT_KEY))
                        ie_str = ie_str.replace(base.toString()+".", "");
//                    else
//                        hasNull = true; //TODO No longer the "return null;"
                }
            }
            
            /*
             * TODO I want the following one still be object
             * $r2 = virtualinvoke r1.<android.content.Intent: android.os.Bundle getExtras()>()
             */
            if (afterbase instanceof InstanceObj
                    && ie_str.contains("<android.content.Intent: android.os.Bundle getExtras()>")) {
                return afterbase;
            }
            
            // Here argus here do not include the base variable
            List<Value> argus = ie.getArgs();
            List<Object> afterargus = new ArrayList<Object>();
            for (int i = 0; i < argus.size(); i++) {
                Value argu = argus.get(i);
                Object afterargu = getConstantFromValueAndMap(argu, factmap);
                if (afterargu != null) {
                    //TODO string replace is not perfect
                    ie_str = ie_str.replace(argu.toString(), afterargu.toString());
                    afterargus.add(afterargu);
                } else {
                    return null;        //TODO We still require all parameters
                }
            }
            
            // Model and simplify InvokeExpr
            String ie_msig = ie.getMethod().getSignature();
            String temp = modelInvokeExpr(ie_str, ie_msig, afterargus, afterbase);
            // Model successfully
            if (temp != null) {
                ie_str = temp;
            }
            // Didn't succeed to model, so we rely on the string.
//            else {
//                if (hasNull)
//                    return null;
//            }
            
            result = ie_str;
        }
        /*
         * BinopExpr
         */
        else if (value instanceof BinopExpr) {
            BinopExpr boe = (BinopExpr)value;
            String boe_str = boe.toString();    //TODO Is string here ok?
            
            Value boe_v1 = boe.getOp1();
            Value boe_v2 = boe.getOp2();
            
            Object after_boe_v1 = getConstantFromValueAndMap(boe_v1, factmap);
            if (after_boe_v1 != null)
                boe_str = boe_str.replace(boe_v1.toString(), after_boe_v1.toString());//TODO string replace is not perfect
            else
                return null;
            
            Object after_boe_v2 = getConstantFromValueAndMap(boe_v2, factmap);
            if (after_boe_v2 != null)
                boe_str = boe_str.replace(boe_v2.toString(), after_boe_v2.toString());//TODO string replace is not perfect
            else
                return null;
            
            // Model and calculate BinopExpr
            String temp = modelBinopExpr(after_boe_v1.toString(),
                                        boe_v1.getType().toString(),
                                        boe.getSymbol(),
                                        after_boe_v2.toString(),
                                        boe_v2.getType().toString());
            if (temp != null)
                boe_str = temp;
            
            result = boe_str;
        }
        /*
         * InstanceField
         * $i0 = r0.<com.kugou.android.dlna.d.b.a: int c>
         */
        else if (value instanceof InstanceFieldRef) {
            Object aftervalue = getConstantFromValueAndMap(value, factmap);
            
            // If value search is already work TODO[But need to exclude previous cases]
            if (aftervalue != null) {
                result = aftervalue;
            }
            // Otherwise, we rely on the InstanceObj
            else {
                InstanceFieldRef ifr = (InstanceFieldRef) value;
                Value base = ifr.getBase();
                Object basevalue = factmap.get(base.toString());//TODO Again, exclude previous cases
                if (basevalue instanceof InstanceObj) {
                    SootField sf = ifr.getField();
                    String str_sf = sf.getSignature();
                    InstanceObj insobj = (InstanceObj) basevalue;
                    Object fieldvalue = insobj.getOneFieldValue(str_sf);
                    if (fieldvalue != null)
                        result = fieldvalue;
                }
            }
        }
        /*
         * Array Index:
         * $i1 = $r7[i2]
         */
        else if (value instanceof ArrayRef) {
            Object aftervalue = getConstantFromValueAndMap(value, factmap);
            
            // If value search is already work TODO[But need to exclude previous cases]
            if (aftervalue != null) {
                result = aftervalue;
            }
            // Otherwise, we rely on the ArrayObj
            else {
                ArrayRef ar = (ArrayRef) value;
                Value base = ar.getBase();
                Object basevalue = factmap.get(base.toString());//TODO Again, exclude previous cases
                if (basevalue instanceof ArrayObj) {
                    Value index = ar.getIndex();
                    Object indexvalue = getConstantFromValueAndMap(index, factmap);
                    if (indexvalue instanceof String) {
                        ArrayObj arrayobj = (ArrayObj) basevalue;
                        Object arrayvalue = arrayobj
                                .getOneIndexValue(indexvalue.toString());
                        if (arrayvalue != null)
                            result = arrayvalue;
                    }
                }
            }
        }
        /*
         * PhiExpr:
         * i8_1 = Phi(i8, i8_2)
         */
        else if (value instanceof PhiExpr) {
            PhiExpr phi_expr = (PhiExpr)value;
            List<ValueUnitPair> phi_vup_args = phi_expr.getArgs();
            
            for (ValueUnitPair phi_vup_arg : phi_vup_args) {
                Value phi_arg = phi_vup_arg.getValue();
                Object aftervalue = getConstantFromValueAndMap(phi_arg, factmap);
                if (aftervalue != null) {
                    result = aftervalue;
                    break;  //TODO currently we simply use the first argument that has constant
                }
            }
        }
        /*
         * TODO Here may have some bugs due to other expressions
         */
        else {
            Object aftervalue = getConstantFromValueAndMap(value, factmap);
            if (aftervalue != null)
                result = aftervalue;
        }
        
        return result;
    }

    /**
     * Get a constant String from the Value directly or from the factmap.
     * 
     * Object can be either String or InstanceObj or ArrayObj.
     * 
     * @param value
     * @param factmap
     * @return null if no Constant is found.
     */
    private Object getConstantFromValueAndMap(Value value, 
            Map<String, Object> factmap) {
        Object result = null;
        String str_value = value.toString();
        
        if (value instanceof Constant) {
            result = str_value;
        }
        /*
         * Construct InstanceObj for new stmts
         * 
         * TODO NewArrayExpr, NewExpr, NewMultiArrayExpr
         * @see https://soot-build.cs.uni-paderborn.de/doc/soot/soot/jimple/AnyNewExpr.html
         * 
         * TODO @this
         */
        else if (value instanceof NewExpr) {
            //
            // TODO we must change this!!!
            // TODO This should be the bug
            //
            if (!str_value.equals("new android.content.Intent") 
                    && !str_value.equals("new android.os.Bundle")
                    && (str_value.startsWith("new java.")
                    || str_value.startsWith("new android.")
                    || str_value.startsWith("new javax."))) {
                result = null;      //TODO need to record its type?
                
            } else {
                MyUtil.printlnOutput(String.format("%s Create an InstanceObj: %s",
                        MyConstant.NormalPrefix, str_value),
                        MyConstant.DEBUG);
                
                NewExpr ne = (NewExpr) value;
                SootClass ne_class = ne.getBaseType().getSootClass();
                result = new InstanceObj(ne_class);
            }
        }
        /*
         * $r0 = newarray (int)[4]
         * r1 = newarray (char)[i6], where i6 can be resolved to a number.
         */
        else if (value instanceof NewArrayExpr) {
            MyUtil.printlnOutput(String.format("%s Create an ArrayObj: %s",
                    MyConstant.NormalPrefix, str_value),
                    MyConstant.DEBUG);
            
            result = new ArrayObj(str_value);
        }
        else {
            Object temp = factmap.get(str_value);
            if (temp != null) {
                result = temp;
                MyUtil.printlnOutput(String.format("%s getConstantFromValueAndMap: %s --> %s",
                        MyConstant.NormalPrefix, str_value, result),
                        MyConstant.DEBUG);
            }
            // But we may find it in the fieldFacts
            else {
                if (value instanceof StaticFieldRef) {
                    Object aftervalue = fieldFacts.get(str_value);//TODO what if an instance object
                    if (aftervalue != null) {
                        result = aftervalue;
                        MyUtil.printlnOutput(String.format(
                                "%s getConstantFromValueAndMap by fieldFacts: %s --> %s",
                                MyConstant.NormalPrefix, str_value, result),
                                MyConstant.WARN);
                    }
                    /*
                     * StaticFieldRef:
                     * $r1 = <org.apache.http.conn.ssl.SSLSocketFactory: org.apache.http.conn.ssl.X509HostnameVerifier ALLOW_ALL_HOSTNAME_VERIFIER>
                     */
                    else {
                        StaticFieldRef staticfr = (StaticFieldRef)value;
                        SootFieldRef sootfr = staticfr.getFieldRef();
                        SootClass sfr_class = sootfr.declaringClass();
                        String str_class = sfr_class.toString();
                        if (PortDetector.apiClassSet.contains(str_class)) {
                            result = str_value;
                            MyUtil.printlnOutput(String.format(
                                    "%s Detect a system API field: %s",
                                    MyConstant.NormalPrefix, str_value),
                                    MyConstant.WARN);
                        }
                    }
                }
            }
        }
        
        return result;
    }
    
    /**
     * Forward analysis of <init>
     * 
     * Can look some <init> method examples
     * 
     * Should be eventually covered by forwardEachNode's cross-method analysis
     * 
     * @param insobj
     * @param method
     * @param factmap
     * @deprecated
     */
    private void markInitMethod(InstanceObj insobj,
            SootMethod method, Map<String, Object> factmap) {
        
        MyUtil.printlnOutput(String.format("%s markInitMethod: %s",
                MyConstant.NormalPrefix, method.getSignature()),
                MyConstant.DEBUG);
        
        Body body = MyUtil.retrieveActiveSSABody(method);
        PatchingChain<Unit> u_chain = body.getUnits();
        String str_this = null;    //To mark the @this variable name
        
        for (Unit unit : u_chain) {
            if (unit instanceof DefinitionStmt) {
                DefinitionStmt ds = (DefinitionStmt) unit;
                Value ds_left = ds.getLeftOp();
                Value ds_right = ds.getRightOp();
                
                /*
                 * r0 := @this: com.kugou.android.mediatransfer.pctransfer.socket.a;
                 */
                if (ds_right.toString().startsWith(THIS_KEY)) {
                    str_this = ds_left.toString();
                }
                /*
                 * Normal case:
                 * r0.<com.kugou.android.mediatransfer.pctransfer.socket.a: int i> = -1;
                 * 
                 * TODO Array:
                 * $r6 = newarray (java.lang.Thread)[4];
                 * r0.<com.kugou.android.mediatransfer.pctransfer.socket.a: java.lang.Thread[] c> = $r6;
                 * 
                 * TODO Invoke:
                 * $r7 = staticinvoke <com.kugou.android.app.KugouApplication: android.content.Context f()>();
                 * $r8 = staticinvoke <com.kugou.framework.common.utils.StringUtil: java.lang.String a(android.content.Context)>($r7);
                 * r0.<com.kugou.android.mediatransfer.pctransfer.socket.a: java.lang.String q> = $r8;
                 * 
                 * TODO Instance Invoke:
                 * r0 := @this: com.studiosol.palcomp3.Backend.Cache.MP3LocalServer;
                 * $i0 = <com.studiosol.palcomp3.Backend.Cache.MP3LocalServer: int PORT>;
                 * specialinvoke r0.<com.studiosol.utillibrary.IO.NanoHTTPD: void <init>(int)>($i0);
                 * 
                 * TODO currently cannot handle untainted field
                 */
                else if (ds_left instanceof InstanceFieldRef) {
                    InstanceFieldRef ifr = (InstanceFieldRef) ds_left;
                    Value base = ifr.getBase();
                    
                    if (str_this.equals(base.toString())) {
                        Object aftervalue = 
                                getConstantFromValueAndMap(ds_right, factmap);
                        if (aftervalue != null) {
                            SootField sf = ifr.getField();
                            String str_sf = sf.getSignature();//TODO <com.kugou.android.mediatransfer.pctransfer.socket.a: int i>?
                            insobj.putOneFieldValue(str_sf, aftervalue);
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Note that the return value is only a String
     * 
     * @param ie_str
     * @param ie_msig
     * @param afterargus
     * @param afterbase
     * @return null if cannot be simplified
     */
    private String modelInvokeExpr(String ie_str, String ie_msig, 
            List<Object> afterargus, Object afterbase) {
        int size = afterargus.size();
        
        MyUtil.printlnOutput(String.format("%s modelInvokeExpr: %s with %d parameters",
                MyConstant.NormalPrefix,
                ie_str, size),
                MyConstant.INFO);
        
        /**
         * model RANDOM api
         * specialinvoke <java.util.Random: void <init>()>()
         * virtualinvoke xxx.<java.util.Random: int nextInt()>())
         * staticinvoke <java.lang.Math: double random()>()
         */
        if (ie_str.contains(MyConstant.RANDOM_RES)
                || ie_msig.contains("java.util.Random")
                || ie_msig.contains("random()")) {
            return MyConstant.RANDOM_RES;
        }
        
        /**
         * See https://bitbucket.org/zout/backdroid/issues/40/getipaddress-and-its-relevant-api
         * getConnectionInfo()>().<android.net.wifi.WifiInfo: int getIpAddress()>()
         * Recursively resolve this by using ie_str instead of ie_msg.
         * So "()" must be added.
         */
        if (ie_str.contains("getIpAddress()")) {
            return "getIpAddress()";
        }
        /*
         * virtualinvoke (new org.apache.commons.net.ftp.FTPClient).<java.net.Socket: java.net.InetAddress getLocalAddress()>()
         * 
         * How about $r1.<java.net.Socket: java.net.InetAddress getLocalAddress()>()?
         */
        if (ie_str.contains("getLocalAddress()")) {
            return "getLocalAddress()";
        }
        /*
         * $r4.<java.net.InetAddress: java.lang.String getHostAddress()>()
         */
        if (ie_str.contains("getHostAddress()")) {
            return "getHostAddress()";
        }
        /*
         * staticinvoke <java.net.InetAddress: java.net.InetAddress getLocalHost()>()
         */
        if (ie_str.contains("getLocalHost()")) {
            return "getLocalHost()";
        }
        /*
         * interfaceinvoke virtualinvoke $r17.<android.widget.EditText: android.text.Editable getText()>().<android.text.Editable: java.lang.String toString()>()
         */
        if (ie_str.contains("getText()")) {
            return "getText()";
        }
        /*
         * [PortResult]idm.internet.download.manager---interfaceinvoke interfaceinvoke $r3.<java.util.List: java.util.Iterator iterator()>().<java.util.Iterator: java.lang.Object next()>()---com.yandex.metrica.impl.ob.de---NOTAG---NOCLICK---<java.net.ServerSocket: void <init>(int)>
         */
        if (ie_str.contains("iterator()")) {
            return "iterator()";
        }
        /*
         * [PortResult]org.sandroproxy---virtualinvoke virtualinvoke virtualinvoke (new org.sandroproxy.ci).<org.sandroproxy.ce: android.support.v4.app.FragmentActivity getActivity()>().<org.sandroproxy.web.SandroProxyWebService: android.content.res.Resources getResources()>().<android.content.res.Resources: java.lang.String getString(int)>(2131427428)---org.a.e.a---NOTAG---NOCLICK---<java.net.ServerSocket: void bind(java.net.SocketAddress)>
         */
        if (ie_str.contains("getResources()")) {
            return "getResources()";
        }
        if (ie_str.contains("<android.database.Cursor: int getInt(int)>")) {
            return "getFromDatabase()";
        }
        if (ie_str.contains("getFromDatabase()")) {
            return "getFromDatabase()";
        }
        
        /**
         * Zero parameter
         * Contain the base variable
         */
        if (size == 0) {
            /*
             * virtualinvoke 63872.<java.lang.Integer: int intValue()>()
             * TODO virtualinvoke "8080".<java.lang.String: java.lang.String trim()>()
             */
            if (ie_msig.equals("<java.lang.Integer: int intValue()>")
                    || ie_msig.equals("<java.lang.String: java.lang.String trim()>")
                    || ie_msig.equals("<java.lang.Object: java.lang.String toString()>")) {
                if (afterbase != null)
                    return afterbase.toString();
                else
                    return null;
            }
            /*
             * i6 = virtualinvoke r0.<java.lang.String: int length()>()
             * TODO other similar funcs?
             */
            if (ie_msig.equals("<java.lang.String: int length()>")) {
                if (afterbase != null) {
                    String basestr = afterbase.toString();
                    if (!basestr.startsWith("\"") || !basestr.endsWith("\""))
                        return null;
                    
                    // The base variable has been resolved.
                    int length = afterbase.toString().length() - 2; //Remove the original ""
                    MyUtil.printlnOutput(String.format("%s modelInvokeExpr: %s --> %d",
                            MyConstant.NormalPrefix,
                            ie_str, length),
                            MyConstant.DEBUG);
                    return String.format("%d", length);
                    
                } else {
                    return null;
                }
            }
        }
        
        /**
         * One parameter
         * 
         * TODO maybe we just use parameter count to do modeling
         */
        if (size == 1) {
            /*
             * <java.net.InetSocketAddress: void <init>(int)>(2211)
             * <java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>("127.0.0.1")
             * <java.lang.String: java.lang.String valueOf(int)>(650)
             * <java.lang.Integer: int parseInt(java.lang.String)>("650")
             */
            if (ie_msig.equals("<java.net.InetSocketAddress: void <init>(int)>")
              ||ie_msig.equals("<java.net.InetAddress: java.net.InetAddress getByName(java.lang.String)>")
              ||ie_msig.equals("<java.lang.String: java.lang.String valueOf(int)>")
              ||ie_msig.equals("<java.lang.Integer: java.lang.Integer valueOf(java.lang.String)>")
              ||ie_msig.equals("<java.lang.Integer: int parseInt(java.lang.String)>")
              ||ie_msig.equals("<java.lang.Integer: java.lang.Integer valueOf(int)>")) {
                return afterargus.get(0).toString();
            }
            /*
             * <java.lang.Math: int abs(int)>(-7777)
             */
            if (ie_msig.equals("<java.lang.Math: int abs(int)>")) {
                String temp = afterargus.get(0).toString();
                if (temp.startsWith("-"))
                    return temp.substring(1);
                else
                    return temp;
            }
            /*
             * <java.net.InetAddress: java.net.InetAddress getByAddress(byte[])>(newarray (byte)[4])
             */
            if (ie_msig.equals("<java.net.InetAddress: java.net.InetAddress getByAddress(byte[])>")) {
                return afterargus.get(0).toString();
            }
            /*
             * null.<java.lang.String: int indexOf(java.lang.String)>("###")
             */
            if (ie_msig.equals("<java.lang.String: int indexOf(java.lang.String)>")) {
                if (afterbase != null) {
                    String basestr = afterbase.toString();
                    String parastr = afterargus.get(0).toString();
                    if (basestr.startsWith("\"") && basestr.endsWith("\""))
                        return String.format("%d", basestr.indexOf(parastr));
                    else
                        return String.format("%d", 0); //TODO 0 or -1?  //TODO or return null?
                } else {
                    return null;
                }
            }
            /*
             * TODO write into paper
             * c9 = virtualinvoke r0.<java.lang.String: char charAt(int)>(i8)
             */
            if (ie_msig.equals("<java.lang.String: char charAt(int)>")) {
                if (afterbase != null) {
                    String basestr = afterbase.toString();
                    String parastr = afterargus.get(0).toString();
                    int paraint;
                    try {
                        paraint = Integer.parseInt(parastr);
                    } catch (NumberFormatException e) {
                        return null;
                    }
                    if (!basestr.startsWith("\"") || !basestr.endsWith("\""))
                        return null;
                    
                    // Both base and para have been resolved.
                    char charstr = basestr.charAt(paraint + 1); //Consider additional "
                    MyUtil.printlnOutput(String.format("%s modelInvokeExpr: %s --> %c",
                            MyConstant.NormalPrefix,
                            ie_str, charstr),
                            MyConstant.DEBUG);
                    return String.format("%c", charstr);
                    
                } else {
                    return null;
                }
            }
            /*
             * virtualinvoke $r2.<android.os.Bundle: int getInt(java.lang.String)>("profile_id")
             * $r2 --> (new android.content.Intent)
             */
            if (ie_msig.equals("<android.os.Bundle: int getInt(java.lang.String)>")) {
                if (afterbase instanceof InstanceObj) {
                    InstanceObj tempinsobj = (InstanceObj) afterbase;
                    Object tempvalue = tempinsobj.getOneFieldValue(
                                        afterargus.get(0).toString());
                    if (tempvalue != null)
                        return tempvalue.toString();
                    else
                        return null;
                } else {
                    return null;
                }
            }
        }
        
        /**
         * Connecting two parameters
         */
        if (size == 2) {
            /*
             * <java.net.InetSocketAddress: void <init>(java.lang.String,int)>("127.0.0.1", 8089)
             * <java.net.InetSocketAddress: void <init>(java.lang.String,int)>(null, 8089)
             */
            if (ie_msig.equals("<java.net.InetSocketAddress: void <init>(java.lang.String,int)>")
              ||ie_msig.equals("<java.net.InetSocketAddress: void <init>(java.net.InetAddress,int)>")) {
                return String.format("%s%s%s",
                        afterargus.get(0).toString(),
                        MyConstant.ParamMiddle,
                        afterargus.get(1).toString());
            }
            /*
             * <java.net.InetAddress: java.net.InetAddress getByAddress(java.lang.String,byte[])>("localhost", newarray (byte)[4])
             */
            if (ie_msig.equals("<java.net.InetAddress: java.net.InetAddress getByAddress(java.lang.String,byte[])>")) {
                return afterargus.get(1).toString();
            }
            /*
             * r17.<android.content.Intent: int getIntExtra(java.lang.String,int)>("httpServerPort", 18888)
             * <android.os.Bundle: int getInt(java.lang.String,int)>("FileExpertHttpPort", 8080)
             */
            if (ie_msig.equals("<android.content.Intent: int getIntExtra(java.lang.String,int)>")
                    || ie_msig.equals("<android.os.Bundle: int getInt(java.lang.String,int)>")) {
                // the correct handling
                if (afterbase instanceof InstanceObj) {
                    InstanceObj tempinsobj = (InstanceObj) afterbase;
                    Object tempvalue = tempinsobj.getOneFieldValue(
                                        afterargus.get(0).toString());
                    if (tempvalue != null)
                        return tempvalue.toString();
                    else {
                        // old handling
                        String intstr = afterargus.get(1).toString();
                        if (intstr.equals("0") || intstr.equals("-1"))
                            return null;
                        else
                            return intstr;
                    }
                        
                }
                // old handling
                else {
                    String intstr = afterargus.get(1).toString();
                    if (intstr.equals("0") || intstr.equals("-1"))
                        return null;
                    else
                        return intstr;
                }
            }
            /*
             * interfaceinvoke $r5.<android.content.SharedPreferences: int getInt(java.lang.String,int)>("SERVER_PORT", 30243)
             */
            if (ie_msig.equals("<android.content.SharedPreferences: int getInt(java.lang.String,int)>")) {
                String intstr = afterargus.get(1).toString();
                if (intstr.equals("0") || intstr.equals("-1"))
                    return null;
                else
                    return intstr;
            }
            /*
             * interfaceinvoke $r2.<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>("prefServerPort", "8080")
             */
            if (ie_msig.equals("<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>")) {
                String intstr = afterargus.get(1).toString();
                if (intstr.equals("\"0\"") || intstr.equals("\"-1\""))
                    return null;
                else
                    return intstr;
            }
        }
        
        return null;
    }
    
    /**
     * Handle 9000 + 1.
     * Becareful with $c1 = c9 ^ 85, where c9 is a char:
     * - '2' ^ 85 --> g
     * - '"' ^ 76 --> n
     * 
     * Currently handle int and char (!!!)
     * TODO could String be also possible? Seems not possible in bytecode
     * 
     * TODO write into paper
     * 
     * @param op1_value
     * @param op1_type
     * @param symbol
     * @param op2_value
     * @param op2_type
     * @return null if not able to be calculated
     */
    private String modelBinopExpr(String op1_value, String op1_type,
            String symbol, String op2_value, String op2_type) {
        try {
            symbol = symbol.trim(); //" + " --> "+"
            
            String res_str = null;  // Could still be null after below
            boolean isBothInt = true;
            boolean isCalculate = false;
            int res_int = -1;
            
            int op1_int, op2_int;
            if (op1_type.equals("char")) {
                isBothInt = false;
                op1_int = op1_value.charAt(0);  //Still use int for calculation
            }
            else
                op1_int = Integer.parseInt(op1_value);
            if (op2_type.equals("char")) {
                isBothInt = false;
                op2_int = op2_value.charAt(0);  //Still use int for calculation
            }
            else
                op2_int = Integer.parseInt(op2_value);
            
            if (symbol.equals("+")) {
                isCalculate = true;
                res_int = op1_int + op2_int;
                
            } else if (symbol.equals("-")) {
                isCalculate = true;
                res_int = op1_int - op2_int;
                
            } else if (symbol.equals("*")) {
                isCalculate = true;
                res_int = op1_int * op2_int;
                
            } else if (symbol.equals("/")) {
                isCalculate = true;
                res_int = op1_int / op2_int;
                
            } else if (symbol.equals("%")) {
                isCalculate = true;
                res_int = op1_int % op2_int;
                
            } else if (symbol.equals("^")) {
                isCalculate = true;
                res_int = op1_int ^ op2_int;
            }
            
            if (isCalculate) {
                if (isBothInt)
                    res_str = String.format("%d", res_int);
                else
                    res_str = String.format("%c", res_int);
            }
            
            if (res_str != null)
                MyUtil.printlnOutput(String.format("%s modelBinopExpr: %s%s%s --> %s. (%s, %s)",
                    MyConstant.NormalPrefix, op1_value, symbol, op2_value, res_str, op1_type, op2_type),
                    MyConstant.DEBUG);
            return res_str;
        
        } catch (Exception e) { //NumberFormatException or charAt exception
            MyUtil.printlnOutput(String.format("%s modelBinopExpr: %s%s%s --> Unsolved. (%s, %s)",
                    MyConstant.NormalPrefix, op1_value, symbol, op2_value, op1_type, op2_type),
                    MyConstant.WARN);
            return null;
        }
    }
    
    /**
     * Extract categorization mark:
     * ClassName+(TagName)+(MethodName)
     * 
     * Normal case:
     * <uk.co.sevendigital.android.library.stream.SDIMediaServer: java.net.ServerSocket b(int,int)>
     * -->
     * "SDIMediaServer"
     * 
     * 
     * Obfuscated case:
     * <com.sina.weibo.media.a.c: void <init>(java.lang.String)>
     * -->
     * "MediaCacheProxy"
     * 
     * 
     * Method case:
     * <com.parse.ParseTestUtils: java.net.ServerSocket mockPushServer()>
     * -->
     * "ParseTestUtils.mockPushServer"
     * 
     * @param initmsig
     * @return Maybe empty
     */
    private String extractMarkName(String msig) {
        String result = null;
        
        // See whether result has been cached
        result = msigMarkMap.get(msig);
        if (result != null)
            return result;
        
        String cname = MyUtil.extractClassNameFromMSig(msig);    //"ParseTestUtils"
        String cutcname = MyUtil.cutShortClassString(cname, 3);  //"e$a" --> "e" --> ""
        String fullcname = MyUtil.extractFullClassFromMSig(msig);//"com.parse.ParseTestUtils"
        StringBuilder sb = new StringBuilder();
        
        String pkgname = PortDetector.PKGmust;
        
        /*
         * Class name, may with some package names
         * 
         * xcxin.filexpert <--> xcxin.filexpert.webserver.e
         * mobi.infolife.appbackup <--> mobi.infolife.wifitransfer.NanoHTTPD
         */
        if (pkgname != null) {
            String[] pkgsplits = pkgname.split("\\.");
            if (pkgsplits.length >= 2) {
                String firsttwo = String.format("%s.%s.", pkgsplits[0], pkgsplits[1]);
                if (fullcname.startsWith(firsttwo)) {
                    String[] cnamesplits = fullcname.split("\\.");
                    for (int i = 2; i < cnamesplits.length; i++) {
                        // Still have pkgsplits[i]
                        if (pkgsplits.length >= i+1) {
                            if (!cnamesplits[i].equals(pkgsplits[i])) {
                                String temp = MyUtil.cutShortClassString(cnamesplits[i], 3);
                                if (!temp.equals("")) {
                                    sb.append(temp);
                                    sb.append(".");
                                }
                            }
                        }
                        // Already have no more pkgsplits
                        else {
                            String temp = MyUtil.cutShortClassString(cnamesplits[i], 3);
                            if (!temp.equals("")) {
                                sb.append(temp);
                                sb.append(".");
                            }
                        }
                    }
                    if (sb.toString().endsWith(".")) {
                        sb.deleteCharAt(sb.length()-1);
                    }
                }
            }
        }
        if (sb.length() == 0) {
            sb.append(cutcname);
        }
        
        /*
         * May add the tag
         * Too short, it should be obfuscated
         * "FTP"
         * 
         * If only three chars, we also need to mark TAG
         */
        if (cutcname.length() < 4) {
            String tagname = findTagName(fullcname);
            if (!tagname.equals(MyConstant.NO_TAG)) {
                if (sb.length() != 0)
                    sb.append(".");
                sb.append(tagname);
            }
        }
        
        /*
         * Not obfuscated, nor NanoHTTPD.
         * Then whether do we add method name
         */
        String mname = MyUtil.extractMethodFromMSig(msig);
        if (MyUtil.containsIgnoreCase(mname, "server")) {
            sb.append(".");
            sb.append(mname);
        }
        
        // Cache result
        result = sb.toString();
        msigMarkMap.put(msig, result);
        
        return result;
    }
    
    /**
     * Analyze target class for finding the TAG
     * 
     * TODO could set an option for this task
     * 
     * @param fullcname
     * @return
     */
    private String findTagName(String fullcname) {
        String result = null;
        
        // See whether result has been cached
        result = classTagMap.get(fullcname);
        if (result != null)
            return result;
        
        SootClass mclass = ClassWorker.loadClass(fullcname);
        Iterator<SootMethod> method_iter = mclass.methodIterator();
        
        Set<String> tagSet = new HashSet<String>();
        
        while (method_iter.hasNext()) {
            SootMethod method = method_iter.next();
            
            if (!method.isConcrete())
                continue;
            
            Body body = MyUtil.retrieveActiveSSABody(method);
            if (body == null)
                continue;
            
            Iterator<Unit> iter_u = body.getUnits().iterator();
            while (iter_u.hasNext()) {
                Unit unit = iter_u.next();
                String unit_str = unit.toString();
                
                /*
                 * staticinvoke <com.kugou.framework.common.utils.y: void a(java.lang.String,java.lang.String)>("WifiAp", $r8);
                 * staticinvoke <android.util.Log: int i(java.lang.String,java.lang.String)>("KugouPlaybackService", "savequeue");
                 * http://docs.oracle.com/javase/6/docs/api/java/util/regex/Pattern.html
                 * https://stackoverflow.com/questions/13948751/string-parse-error    sysCallName.split("[(]");
                 */
                if (unit_str.matches(".*staticinvoke.* [a-zA-z][(]java.lang.String,java.lang.String[)]>[(]\".*")) {
                    MyUtil.printlnOutput(String.format("%s Match: %s",
                            MyConstant.NormalPrefix, unit_str),
                            MyConstant.DEBUG);
                    int begindex = unit_str.indexOf("\"");
                    int endindex = unit_str.indexOf("\"", begindex+1);
                    String onetag = unit_str.substring(begindex+1, endindex);
                    String temp = MyUtil.cutShortClassString(onetag, 3);
                    if (!temp.equals(""))
                        tagSet.add(temp);
                }
            }
        }
        
        // Make result
        if (tagSet.isEmpty()) {
            result = MyConstant.NO_TAG; //TODO
        } else {
            StringBuilder sb = new StringBuilder();
            for (String onetag : tagSet) {
                sb.append(onetag);
                sb.append(",");
            }
            sb.deleteCharAt(sb.length()-1);
            result = sb.toString();
        }
        
        // Cache result
        classTagMap.put(fullcname, result);
        
        return result;
    }

}
