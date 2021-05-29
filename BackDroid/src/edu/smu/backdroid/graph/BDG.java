package edu.smu.backdroid.graph;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import soot.SootClass;
import soot.SootField;
import soot.SootFieldRef;
import soot.Unit;
import soot.Value;
import soot.jimple.ArrayRef;
import soot.jimple.BinopExpr;
import soot.jimple.CastExpr;
import soot.jimple.Constant;
import soot.jimple.FieldRef;
import soot.jimple.InstanceFieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.StaticFieldRef;
import edu.smu.backdroid.analysis.FieldWorker;
import edu.smu.backdroid.analysis.UnitWorker;
import edu.smu.backdroid.structure.BoolObj;
import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;

/**
 * BDG: BackwardDependenceGraph starting from the target parameter node
 * 
 * @author Daoyuan
 * @since 13-04-06
 * @restart 17-06-06
 * @see UnitGraph
 */
public class BDG {
    
    /**
     * E.g.: The initial target method signature
     */
    private String initSig;
    
    /**
     * Store nodes in a layered manner
     */
    protected List<BDGUnit> nodeList;
    
    protected List<BDGUnit> fieldNodes;
    
    /**
     * Store edges.
     * Change from List to Set
     * For handling complex cases such as org.apache.commons.net.ftp.FTPClient_BDG
     */
    protected Set<BDGEdge> edgeSet;
    
    protected Set<BDGEdge> fieldEdges;
    
    /**
     * The first node
     */
    protected BDGUnit initNode;
    
    /**
     * Keep tracking the last node along the way
     * The current node, more precisely
     */
    protected BDGUnit lastNormalNode;
    
    protected BDGUnit lastFieldNode;
    
    /**
     * The end points of backward slicing
     * 
     * We cannot use Set for nodeList, because we rely on its order to get last node.
     */
    protected Set<BDGUnit> normalTails;
    
    protected List<BDGUnit> fieldTails; //Here it is not sensitive to redundancy
    
    protected Set<BDGUnit> fakeTails;   //For those are dead codes due to library
    
    /**
     * A global taint map for the whole graph
     */
    protected Map<String, Set<String>> taintMap;
    
    /**
     * Save the String-based fields and their original StaticFieldRef
     */
    protected Map<String, StaticFieldRef> fieldRefs;
    
    /**
     * Save *all* the String-based object fields along the way
     */
    protected Set<String> objectFieldSet;
    
    /**
     * Construct BDG
     * 
     * @param initMethod
     */
    public BDG(String initMethod) {
        this.initSig = initMethod;
        
        this.nodeList = new ArrayList<BDGUnit>();
        this.edgeSet = new HashSet<BDGEdge>();
        this.taintMap = new HashMap<String, Set<String>>();
        this.objectFieldSet = new HashSet<String>();
        this.normalTails = new HashSet<BDGUnit>();
        this.fakeTails = new HashSet<BDGUnit>();
        
        /*
         * Create a field map
         * 
         * TODO We shall have a field map for each path?
         */
        Set<String> fieldset = new HashSet<String>();
        this.taintMap.put(MyConstant.GLOBALFIELD, fieldset);
        
        /*
         * For handling static fields
         */
        this.fieldRefs = new HashMap<String, StaticFieldRef>();
        this.fieldNodes = new ArrayList<BDGUnit>();
        this.fieldEdges = new HashSet<BDGEdge>();
        this.fieldTails = new ArrayList<BDGUnit>(); //We need to leverage its order
        
        // Reset the graph node ID
        BDGUnit.NODE_ID = 0;
    }
    
    /**
     * 
     * @param initUnit
     * @param containerMSig
     * @return false if no parameters to be tracked
     */
    public boolean addInitNode(Unit initUnit, String containerMSig) {
        boolean result = false;
        
        /*
         * Determine and add the parameter taints
         */
        InvokeExpr invokeexpr = UnitWorker.v().getInvokeExpr(initUnit);
        if (invokeexpr != null) {
            List<Value> args = invokeexpr.getArgs();
            for (Value arg : args) {
                MyUtil.printlnOutput(String.format("%s Arg: %s",
                        MyConstant.ForwardPrefix, arg.toString()),
                        MyConstant.WARN);
                
                boolean isAdded = this.addOneTaintValue(arg, containerMSig);
                if (isAdded)
                    result = true;
            }
        }
        
        /*
         * Add the initial node into graph, no matter the result is true or not.
         * Even if all parameters are constants, we then can use this node to generate results.
         */
        BDGUnit initNode = new BDGUnit(containerMSig, initUnit);
        this.initNode = initNode;
        this.addBDGNote(initNode, false);
        
        MyUtil.printlnOutput(String.format("%s addInitNode: %s",
                MyConstant.NormalPrefix, initUnit.toString()),
                MyConstant.DEBUG);
        
        //
        // TODO If we later introduce reachability analysis
        // Is this still necessary?
        //
        if (!result) {
//            checkTailNode();
            return true;    //TODO
        }
        
        return result;
    }
    
    public void addInitFieldNode(Unit unit, String msig) {
        MyUtil.printlnOutput(String.format("%s addInitFieldNode: %s",
                MyConstant.NormalPrefix, unit.toString()),
                MyConstant.DEBUG);
        
        BDGUnit node = new BDGUnit(msig, unit);
        this.addBDGNote(node, true);
        
        // TODO checkTailNode
    }
    
    /**
     * For normal node creation, with no return edge
     * 
     * @param unit
     * @param msig
     * @return
     */
    public BDGUnit addNormalNode(Unit unit, String msig,
            final boolean isStaticTrack) {
        // retrieve the last node
        BDGUnit dst_node = this.getLastNode(isStaticTrack);
        
        // create a new node as the source node
        MyUtil.printlnOutput(String.format("%s addNormalNode: %s",
                MyConstant.NormalPrefix, unit.toString()),
                MyConstant.DEBUG);
        BDGUnit src_node = new BDGUnit(msig, unit);
        this.addBDGNote(src_node, isStaticTrack);
        
        // create the edge from src to dst
        this.createBDGEdge(src_node, dst_node, isStaticTrack);
        
        return src_node;
    }
    
    /**
     * For node creation that may require to create a return edge
     * 
     * @param unit
     * @param msig
     * @param isReturn
     * @return
     */
    public BDGUnit addNormalNode(Unit unit, String msig,
            BoolObj isReturn, final boolean isStaticTrack) {
        // retrieve the last node
        BDGUnit dst_node = this.getLastNode(isStaticTrack);
        
        // create a new node as the source node
        BDGUnit src_node = new BDGUnit(msig, unit);
        this.addBDGNote(src_node, isStaticTrack);
        
        // create the edge from src to dst
        if (isReturn.getValue()) {
            MyUtil.printlnOutput(String.format("%s addReturnNode: %s",
                    MyConstant.NormalPrefix, unit.toString()),
                    MyConstant.DEBUG);
            this.createReturnBDGEdge(src_node, dst_node, isStaticTrack);
            isReturn.setValue(false);   //!!! Must reset its value TODO
            
        } else {
            MyUtil.printlnOutput(String.format("%s addNormalNode: %s",
                    MyConstant.NormalPrefix, unit.toString()),
                    MyConstant.DEBUG);
            this.createBDGEdge(src_node, dst_node, isStaticTrack);
        }
        
        return src_node;
    }
    
    public void setTailNode(BDGUnit node, final boolean isStaticTrack) {
        MyUtil.printlnOutput(String.format("%s setTailNode: %s",
                MyConstant.ForwardPrefix, node.getUnitStr()),
                MyConstant.WARN);
        
        if (isStaticTrack)
            this.fieldTails.add(node);
        else
            this.normalTails.add(node);
    }
    
    // TODO would isStaticTrack cause any problem?
    public void setFakeTail(BDGUnit node, final boolean isStaticTrack) {
        MyUtil.printlnOutput(String.format("%s setFakeTail: %s",
                MyConstant.ForwardPrefix, node.getUnitStr()),
                MyConstant.WARN);
        
        if (isStaticTrack)
            this.fieldTails.add(node);
        else
            this.fakeTails.add(node);
    }
    
    /**
     * If there is only one node (i.e., initNode),
     * we also need to set it to be the tail node.
     */
    private void checkTailNode() {
        if (this.nodeList.size() == 1)
            setTailNode(this.initNode, false);
    }
    
    /**
     * The basic function for adding various Value (including those Expr) to be taints
     * 
     * The getUseBoxes() way to retrieve values has some problems.
     * For example, it cannot handle the following cases:
     * -- $i0
     * -- r0.<com.afollestad.neuron.Terminal$1: com.afollestad.neuron.Terminal this$0> would only taint r0
     * -- @this: com.afollestad.neuron.Terminal$1 Do not taint @this variable at all
     * 
     * We shall also record the this and parameter variables below.
     * r0 := @this: com.afollestad.neuron.Terminal;
     * r1 := @parameter0: com.afollestad.neuron.Neuron;
     * 
     * @param value
     * @param msig
     * @see ParaContainer.addTaintValue()
     */
    public void addTaintValue(Value value, String msig) {
        if (value == null)
            return;
        
        //
        // Simplify CastExpr
        // -- CastExpr: (java.net.InetAddress) $r56, Op: $r56
        //
        if (value instanceof CastExpr) {
            CastExpr ce = (CastExpr)value;
            value = ce.getOp();
            MyUtil.printlnOutput(String.format("%s CastExpr: %s, Op: %s",
                    MyConstant.NormalPrefix, ce.toString(), value.toString()),
                    MyConstant.DEBUG);
        }
        
        //
        // Split some Expr which are also Value.
        //
        // 1) InvokeExpr from InvokeStmt: (The base variable can be tainted again, no problem!)
        // ------ specialinvoke $r8.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>($r9, $i0)
        // 2) InvokeExpr from DefinitionStmt:
        // ------ $i1 = staticinvoke <java.lang.Math: int abs(int)>($i0);
        // ------ $i0 = virtualinvoke $r0.<java.util.Random: int nextInt()>()  [Shall taint $r0 too!]
        // ------ $i0 = staticinvoke <com.kugou.framework.e.b.b.a: int c()>()
        // ------ $i0 = staticinvoke <com.kugou.framework.e.b.b.a: int c($i1)>()
        // ------ $r51 = interfaceinvoke r12.<java.util.Map$Entry: java.lang.Object getKey()>() too complicated in com.samremote.view-16
        // 3) BinopExpr: 8000 + $i2
        //
        // TODO other Expr candidate?
        //
        if (value instanceof InvokeExpr) {
            InvokeExpr ie = (InvokeExpr)value;
            
            if (ie instanceof InstanceInvokeExpr) {
                InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                Value base = iie.getBase();
                this.addOneTaintValue(base, msig);
            }
            
            // Here argus here do not include the base variable
            List<Value> argus = ie.getArgs();
            for (Value argu : argus) {
                this.addOneTaintValue(argu, msig);
            }
        }
        else if (value instanceof BinopExpr) {
            BinopExpr boe = (BinopExpr)value;
            Value boe_v1 = boe.getOp1();
            Value boe_v2 = boe.getOp2();
            this.addOneTaintValue(boe_v1, msig);
            this.addOneTaintValue(boe_v2, msig);
        }
        //
        // The normal cases such as follows:
        // -- $i0
        // -- @this: com.afollestad.neuron.Terminal$1
        // -- @parameter0: com.afollestad.neuron.Neuron
        // -- r0.<com.afollestad.neuron.Terminal$1: com.afollestad.neuron.Terminal this$0>
        //
        else {
            this.addOneTaintValue(value, msig);
        }
    }
    
    /**
     * The actual internal function for adding one raw Value to be taints.
     * 
     * Just need to determine Constant or not.
     * But how to handle fields and arrays is a key problem.
     * Array must be handled here, because it may be used in BinopExpr.
     * 
     * TODO any other Ref?
     * 
     * @param value The Value here does not contain complex structures.
     * @param msig
     * @return False if the Value is not added
     */
    private boolean addOneTaintValue(Value value, String msig) {
        if (value == null)
            return false;
        
        if (value instanceof Constant)
            return false;
        
        /*
         * Handle fields
         */
        if (value instanceof FieldRef) {
            //
            // For r0.<com.afollestad.neuron.Terminal: int mPort>
            // We shall taint both r0 and the whole field
            //
            if (value instanceof InstanceFieldRef) {
                InstanceFieldRef ifr = (InstanceFieldRef) value;
                Value base = ifr.getBase();
                
                this.getTaintSet(msig).add(value.toString());
                MyUtil.printlnOutput(String.format("%s Add %s to the method taint set",
                        MyConstant.NormalPrefix, value.toString()),
                        MyConstant.WARN);
                
                this.getTaintSet(msig).add(base.toString());
                MyUtil.printlnOutput(String.format("%s Add %s to the method taint set",
                        MyConstant.NormalPrefix, base.toString()),
                        MyConstant.WARN);
                
                SootFieldRef sfr = ifr.getFieldRef();
                String sfr_sig = sfr.getSignature();//TODO field class hierarchy
                this.objectFieldSet.add(sfr_sig);
                MyUtil.printlnOutput(String.format("%s Add %s to the object field set",
                        MyConstant.NormalPrefix, sfr_sig),
                        MyConstant.WARN);
            }
            //
            // TODO always the StaticFieldRef class?
            //
            else if (value instanceof StaticFieldRef) {
                String str_value = value.toString();
                this.getTaintSet(MyConstant.GLOBALFIELD).add(str_value);
                MyUtil.printlnOutput(String.format("%s Add %s to the GLOBALFIELD taint set",
                        MyConstant.NormalPrefix, value.toString()),
                        MyConstant.WARN);
                
                StaticFieldRef sfr = (StaticFieldRef) value;
                this.fieldRefs.put(str_value, sfr);
                
                /*
                 * Find out which methods contain this field.
                 * <xcxin.filexpert.ftpserver.FTPServerService: int h>
                 * |0011: sget v2, Lxcxin/filexpert/ftpserver/FTPServerService;.h:I // field@591b
                 * |000b: sput v1, Lxcxin/filexpert/ftpserver/FTPServerService;.h:I // field@591b
                 */
                FieldWorker.v().searchFieldFuncs(value.toString());
            }
        }
        /*
         * Also handle array
         * ArrayRef: r1[i5]
         */
        else if (value instanceof ArrayRef) {
            ArrayRef ar = (ArrayRef) value;
            Value base  = ar.getBase();
            Value index = ar.getIndex();
            
            this.getTaintSet(msig).add(value.toString());
            MyUtil.printlnOutput(String.format("%s Add %s to the method taint set",
                    MyConstant.NormalPrefix, value.toString()),
                    MyConstant.WARN);
            if (!(base instanceof Constant)) {
                this.getTaintSet(msig).add(base.toString());
                MyUtil.printlnOutput(String.format("%s Add %s to the method taint set",
                        MyConstant.NormalPrefix, base.toString()),
                        MyConstant.WARN);
            }
            if (!(index instanceof Constant)) {
                this.getTaintSet(msig).add(index.toString());
                MyUtil.printlnOutput(String.format("%s Add %s to the method taint set",
                        MyConstant.NormalPrefix, index.toString()),
                        MyConstant.WARN);
            }
        }
        /*
         * Normal case
         */
        else {
            this.getTaintSet(msig).add(value.toString());
            MyUtil.printlnOutput(String.format("%s Add %s to the method taint set",
                    MyConstant.NormalPrefix, value.toString()),
                    MyConstant.DEBUG);
        }
        
        return true;
    }
    
    public void addTaintValue(String value, String msig) {
        this.getTaintSet(msig).add(value);
        MyUtil.printlnOutput(String.format("%s Add %s to the method taint set",
                MyConstant.NormalPrefix, value),
                MyConstant.DEBUG);
    }
    
    /**
     * Four cases:
     * - Normal: $r7 = r0.<com.jcraft.jsch.PortWatcher: java.net.InetAddress boundaddress>
     * - InstanceFields: r0.<com.jcraft.jsch.PortWatcher: java.net.InetAddress boundaddress> = $r4
     * ==Remove both? But other taint may still have r0
     * --Static fields, the most important thing...
     * --Array: $r0[3] = 2612;
     * 
     * TODO other cases?
     * 
     * @param value
     * @param msig
     */
    public void removeTaintValue(Value value, String msig) {
        /*
         * fields
         */
        if (value instanceof FieldRef) {
            /*
             * Instance field
             */
            if (value instanceof InstanceFieldRef) {
                this.getTaintSet(msig).remove(value.toString());
                
                // See whether there are other r0.<...>
                InstanceFieldRef ifr = (InstanceFieldRef) value;
                Value base = ifr.getBase();
                String basestr = base.toString();
                String keyword = String.format("%s.<", basestr);
                
                boolean hasMoreInstance = false;
                Set<String> taintset = this.getTaintSet(msig);
                for (String taint : taintset) {
                    if (taint.startsWith(keyword)) {
                        hasMoreInstance = true;
                        break;
                    }
                }
                
                // If no more instances, we also delete r0
                if (!hasMoreInstance)
                    this.getTaintSet(msig).remove(basestr);
            }
            /*
             * Static field
             */
            else if (value instanceof StaticFieldRef) {
                this.getTaintSet(MyConstant.GLOBALFIELD).remove(value.toString());
            }
        }
        /*
         * Array: $r0[3]
         * Directly remove the entire $r0[3], if any.
         * But if there is $r0, it will still be there.
         */
        else if (value instanceof ArrayRef) {
            this.getTaintSet(msig).remove(value.toString());
        }
        /*
         * Normal case: $r7
         */
        else {
            this.getTaintSet(msig).remove(value.toString());
        }
    }
    
    /**
     * Get or Create a taint set for a particular method
     * 
     * @param methodName
     * @return
     */
    public Set<String> getTaintSet(String methodName) {
        Set<String> res_set = this.taintMap.get(methodName);
        
        // initialize
        if (res_set == null) {
            res_set = new HashSet<String>();
            this.taintMap.put(methodName, res_set);
        }
        
        return res_set;
    }
    
    public Set<String> getObjectFieldSet() {
        return this.objectFieldSet;
    }
    
    /**
     * Get all unique SootClass for static fields.
     * 
     * @return
     */
    public Set<SootClass> getAllFieldClasses() {
        Set<SootClass> result = new HashSet<SootClass>();
        
        Set<String> fieldset = getTaintSet(MyConstant.GLOBALFIELD);
        for (String str_field : fieldset) {
            MyUtil.printlnOutput(String.format("%s getAllFieldClasses: %s",
                    MyConstant.NormalPrefix, str_field),
                    MyConstant.DEBUG);
            
            StaticFieldRef sfr = getOneFieldRef(str_field);
            SootField sf = sfr.getField();
            SootClass sf_class = sf.getDeclaringClass();
            result.add(sf_class);
        }
        
        return result;
    }
    
    private StaticFieldRef getOneFieldRef(String str_field) {
        return this.fieldRefs.get(str_field);
    }
    
    /**
     * Add node into the list and set it to be the last node
     * 
     * @param node
     */
    private void addBDGNote(BDGUnit node, final boolean isStaticTrack) {
        if (isStaticTrack)
            this.fieldNodes.add(node);
        else
            this.nodeList.add(node);
        
        this.setLastNode(node, isStaticTrack);
    }
    
    public BDGUnit getLastNode(final boolean isStaticTrack) {
        if (isStaticTrack)
            return this.lastFieldNode;
        else
            return this.lastNormalNode;
    }
    
    public void setLastNode(BDGUnit node, final boolean isStaticTrack) {
        if (isStaticTrack)
            this.lastFieldNode = node;
        else
            this.lastNormalNode = node;
    }
    
    public BDGUnit getInitNode() {
        return this.initNode;
    }
    
    /**
     * Create an edge and add it to the list
     * 
     * @param src_node
     * @param dst_node
     */
    private void createBDGEdge(BDGUnit src_node, BDGUnit dst_node,
            final boolean isStaticTrack) {
        BDGEdge edge;
        
        String src_msig = src_node.getMSig();
        String src_unit = src_node.getUnitStr();
        String dst_msig = dst_node.getMSig();
        String dst_unit = dst_node.getUnitStr();
        
        if (dst_msig.equals(src_msig)) {
            if (dst_unit.equals(src_unit))
                edge = new BDGEdge(src_node, dst_node, BDGEdgeType.SELFLOOP_EDGE);
            else
                edge = new BDGEdge(src_node, dst_node, BDGEdgeType.DIRECT_EDGE);
            
        } else {
            edge = new BDGEdge(src_node, dst_node, BDGEdgeType.CROSS_EDGE);
        }
        
        if (isStaticTrack)
            this.fieldEdges.add(edge);
        else
            this.edgeSet.add(edge);
    }
    
    /**
     * Call after an iterative backwardOneMethod
     * 
     * @param src_node
     */
    public void createSpecialBDGEdge(BDGUnit src_node,
            final boolean isStaticTrack) {
        BDGUnit dst_node = this.getLastNode(isStaticTrack);
        
        this.createBDGEdge(src_node, dst_node, isStaticTrack);
    }
    
    /**
     * 
     * @param src_node
     * @param dst_node
     */
    private void createReturnBDGEdge(BDGUnit src_node, BDGUnit dst_node,
            final boolean isStaticTrack) {
        BDGEdge edge;
        
        if (src_node.equals(dst_node))
            edge = new BDGEdge(src_node, dst_node, BDGEdgeType.SELFLOOP_EDGE);
        else
            edge = new BDGEdge(src_node, dst_node, BDGEdgeType.RETURN_EDGE);
        
        if (isStaticTrack)
            this.fieldEdges.add(edge);
        else
            this.edgeSet.add(edge);
    }
    
    /**
     * Get outgoing edge of a BDG node
     * 
     * This function is expensive.
     * 
     * @param node
     * @return
     */
    public List<BDGEdge> getOutgoingEdge(BDGUnit node,
            final boolean isStaticTrack) {
        List<BDGEdge> result = new ArrayList<BDGEdge>();
        
        Set<BDGEdge> edges;
        if (isStaticTrack)
            edges = this.fieldEdges;
        else
            edges = this.edgeSet;
        
        for (BDGEdge edge : edges) {
            BDGUnit srcnode = edge.getSource();
            if (srcnode.equals(node))
                result.add(edge);
        }
        
        return result;
    }
    
    /**
     * Get incoming edge of a BDG node
     * 
     * TODO set isStaticTrack
     * 
     * @param node
     * @return
     */
    public List<BDGEdge> getIncomingEdge(BDGUnit node) {
        List<BDGEdge> result = new ArrayList<BDGEdge>();
        
        for (BDGEdge edge : this.edgeSet) {
            BDGUnit tgtnode = edge.getTarget();
            if (tgtnode.equals(node))
                result.add(edge);
        }
        
        return result;
    }
    
    /**
     * 
     * @return
     * @see BDGToDotGraph
     */
    public Map<String, List<BDGUnit>> getNodeListMap(final boolean isStaticTrack) {
        Map<String, List<BDGUnit>> nodelistMap = new HashMap<String, List<BDGUnit>>();
        
        List<BDGUnit> nodeList;
        if (isStaticTrack)
            nodeList = this.fieldNodes;
        else
            nodeList = this.nodeList;
        
        for (BDGUnit node : nodeList) {
            String msig = node.getMSig();
            
            List<BDGUnit> nodelist = nodelistMap.get(msig);
            if (nodelist == null) {
                nodelist = new ArrayList<BDGUnit>();
                nodelist.add(node);
                nodelistMap.put(msig, nodelist);
                
            } else {
                nodelist = nodelistMap.get(msig);
                nodelist.add(node);     // Will also reflect into nodelistMap
            }
        }
        
        return nodelistMap;
    }
    
    /**
     * return an iterator over the edge list
     * 
     * @return
     */
    public Iterator<BDGEdge> edgeIterator(final boolean isStaticTrack) {
        if (isStaticTrack)
            return this.fieldEdges.iterator();
        else
            return this.edgeSet.iterator();
    }
    
    public Set<BDGUnit> getNormalTails() {
        return this.normalTails;
    }
    
    public List<BDGUnit> getFieldTails() {
        return this.fieldTails;
    }
    
    public Set<BDGUnit> getFakeTails() {
        return this.fakeTails;
    }

    public String getInitSig() {
        return initSig;
    }

    public void setInitSig(String initsig) {
        this.initSig = initsig;
    }
    
}
