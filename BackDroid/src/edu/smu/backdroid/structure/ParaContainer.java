package edu.smu.backdroid.structure;

import edu.smu.backdroid.PortDetector;
import edu.smu.backdroid.analysis.UnitWorker;
import soot.SootMethod;
import soot.Value;
import soot.jimple.BinopExpr;
import soot.jimple.CastExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.NullConstant;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;

public class ParaContainer {
    
    private ParaHead head;
    
    /**
     * The taint value map
     */
    private LinkedHashMap<Value, VLMContainer> valuemap;
    
    private Value flag;
    
    public ParaContainer(ParaHead head) {
        this.head = head;
        this.valuemap = new LinkedHashMap<Value, VLMContainer>();
    }
    
    /**
     * add init taint value for one argument
     * 
     * @param value
     */
    public void addInitTaintValue(Value value, SootMethod method) {
        VLMContainer vlm = new VLMContainer();
        vlm.addOneValue(value, method);
        
        // null constant (instead of null) as the flag!!
        NullConstant nullobj = NullConstant.v();
        this.valuemap.put(nullobj, vlm);
        this.flag = nullobj;
        
        // TODO in the beginning, it must be raw value?
        if (!UnitWorker.v().isTraceThisValue(value)) {
            vlm.setIsFinished(true);
            this.head.setIsFinished(true);
        }
    }
    
    /**
     * add normal taint value during analysis
     * 
     * @param index
     * @param value
     */
    public List<Value> addTaintValue(Value index, Value value, SootMethod method) {
        List<Value> newindexlist = new ArrayList<Value>();
        
        //
        // simplify CastExpr
        // -- CastExpr: (java.net.InetAddress) $r56, Op: $r56
        //
        if (value instanceof CastExpr) {
            CastExpr ce = (CastExpr)value;
            System.out.println("--> CastExpr: "+ce+", Op: "+ce.getOp());
            value = ce.getOp();
        }
        
        // add
        VLMContainer vlm = this.valuemap.get(index);
        vlm.addOneValue(value, method);
        
        //
        // check method == null
        // possible when backwardUnit(), but causes problem when split below
        //
        if (method == null) {
            method = vlm.getCurrentMethod();
        }
        
        //
        // Split the taint if:
        //
        // 1) InvokeExpr from InvokeStmt:
        // ------ specialinvoke $r8.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>($r9, $i0)
        // 2) InvokeExpr from DefinitionStmt:
        // ------ $i1 = staticinvoke <java.lang.Math: int abs(int)>($i0);
        // ------ $i0 = virtualinvoke $r0.<java.util.Random: int nextInt()>()   $r0 is NOT finished
        // ------ $i0 = staticinvoke <com.kugou.framework.e.b.b.a: int c()>()   NOT finished
        // ------ TODO $i0 = staticinvoke <com.kugou.framework.e.b.b.a: int c($i1)>() how to handle this?
        // ------ $r51 = interfaceinvoke r12.<java.util.Map$Entry: java.lang.Object getKey()>() too complicated in com.samremote.view-16
        // 3) BinopExpr: 8000 + $i2
        //
        // TODO other candidate?
        //
        if (value instanceof InvokeExpr) {
            // handle parameters
            InvokeExpr ie = (InvokeExpr)value;
            List<Value> argus = ie.getArgs();
            for (Value argu : argus) {
                if (UnitWorker.v().isTraceThisValue(argu)) {
                    VLMContainer argu_vlm = new VLMContainer();
                    argu_vlm.addOneValue(argu, method);
                    this.valuemap.put(argu, argu_vlm);//TODO what if same value name? But their object is different, right?
                    newindexlist.add(argu);
                }
            }
            
            // handle finished or not
            SootMethod ie_method = ie.getMethod();
            String ie_classname = ie_method.getDeclaringClass().getName();
            String ie_methodname = ie_method.getName();
            
            if (PortDetector.apiClassSet.contains(ie_classname))
                vlm.setIsFinished(true);
            else if (ie_methodname.equals("<init>"))    //TODO right? seems need to remove this
                vlm.setIsFinished(true);
            
            // TODO handle base object
            // com.samremote.view-16 will error
//            if (ie instanceof InstanceInvokeExpr) {
//                InstanceInvokeExpr iie = (InstanceInvokeExpr)ie;
//                Value iie_base = iie.getBase();
//                
//                if (!ie_methodname.equals("<init>")) {
//                    VLMContainer base_vlm = new VLMContainer(); 
//                    base_vlm.addOneValue(iie_base, method);
//                    this.valuemap.put(iie_base, base_vlm);
//                    newindexlist.add(iie_base);
//                }
//            }
            
        }
        else if (value instanceof BinopExpr) {
            BinopExpr boe = (BinopExpr)value;
            
            Value boe_v1 = boe.getOp1();
            if (UnitWorker.v().isTraceThisValue(boe_v1)) {
                VLMContainer boe_vlm = new VLMContainer();
                boe_vlm.addOneValue(boe_v1, method);
                this.valuemap.put(boe_v1, boe_vlm);
                newindexlist.add(boe_v1);
            }
            
            Value boe_v2 = boe.getOp2();
            if (UnitWorker.v().isTraceThisValue(boe_v2)) {
                VLMContainer boe_vlm = new VLMContainer();
                boe_vlm.addOneValue(boe_v2, method);
                this.valuemap.put(boe_v2, boe_vlm);
                newindexlist.add(boe_v2);
            }
            
            vlm.setIsFinished(true);
        }
        else {
            if (!UnitWorker.v().isTraceThisValue(value))
                vlm.setIsFinished(true);
        }
        
        return newindexlist;
    }
    
    /**
     * get the current taints in a list of TaintContainer
     * 
     * In each ParaContainer, taint index is unique
     * 
     * @return
     */
    public List<TaintContainer> getCurrentTaints() {
        if (this.head.getIsFinished())
            return null;
        
        List<TaintContainer> results = new ArrayList<TaintContainer>();
        
        for (Entry<Value, VLMContainer> e : this.valuemap.entrySet()) {
            VLMContainer vlm = e.getValue();
            
            if (vlm.getIsFinished())
                continue;
            
            Value last = vlm.getValuelist().getLast();
            TaintContainer tc = new TaintContainer(e.getKey(), last);
            results.add(tc);
        }
        
        return results;
    }
    
    public VLMContainer getVLMContainer(Value index) {
        return this.valuemap.get(index);
    }
    
    public boolean getIsFinished() {
        /*
         * if result is already cached
         */
        if (this.head.getIsFinished())
            return true;
        
        /*
         * otherwise, we don't know the result, so analyze it once.
         */
        boolean result;
        
        // not necessary for appinventor.ai_jim_fass.NextBigThing
//        for (VLMContainer vlm : this.valuemap.values()) {
//            if (!vlm.getIsFinished()) {
//                result = false;
//                break;
//            }
//        }
        VLMContainer vlm = this.valuemap.get(flag);
        result = isLastFinished(vlm);
        
        this.head.setIsFinished(result);
        
        return result;
    }
    
    /**
     * Learn from transformResult
     * TODO so if it changes, here also change
     * 
     * @param vlm
     * @return
     */
    public boolean isLastFinished(VLMContainer vlm) {
        Value last = vlm.getValuelist().getLast();
        boolean result = true;
        
        if (last instanceof InvokeExpr) {
            InvokeExpr ie = (InvokeExpr)last;
            List<Value> argus = ie.getArgs();
            for (Value argu : argus) {
                VLMContainer tempvlm = this.valuemap.get(argu);
                if (tempvlm != null) {
                    if (!tempvlm.getIsFinished()) {
                        result = false;
                        break;
                    }
                }
            }
            // TODO do not handle base object currently
        }
        else if (last instanceof BinopExpr) {
            BinopExpr boe = (BinopExpr)last;
            
            Value boe_v1 = boe.getOp1();
            VLMContainer tempvlm1 = this.valuemap.get(boe_v1);
            if (tempvlm1 != null) {
                if (!tempvlm1.getIsFinished()) {
                    result = false;
                }
            }
            
            Value boe_v2 = boe.getOp2();
            VLMContainer tempvlm2 = this.valuemap.get(boe_v2);
            if (tempvlm2 != null) {
                if (!tempvlm2.getIsFinished()) {
                    result = false;
                }
            }
        }
        // if only the simple type, such as {@parameter1: int}
        else {
            if (!vlm.getIsFinished()) {
                result = false;
            }
        }
        
        return result;
    }
    
    public String getResult() {
        String result = "";
        
        VLMContainer vlm = this.valuemap.get(flag);
        result = transformResult(vlm);
        
        return result;
    }
    
    public String transformResult(VLMContainer vlm) {
        Value last = vlm.getValuelist().getLast();
        String result = last.toString();
        
        if (last instanceof InvokeExpr) {
            InvokeExpr ie = (InvokeExpr)last;
            List<Value> argus = ie.getArgs();
            for (Value argu : argus) {
                VLMContainer tempvlm = this.valuemap.get(argu);
                if (tempvlm != null) {
                    result = result.replace(argu.toString(), transformResult(tempvlm));
                }
            }
            // TODO do not handle base object currently
            
        }
        else if (last instanceof BinopExpr) {
            BinopExpr boe = (BinopExpr)last;
            
            Value boe_v1 = boe.getOp1();
            VLMContainer tempvlm1 = this.valuemap.get(boe_v1);
            if (tempvlm1 != null) {
                result = result.replace(boe_v1.toString(), transformResult(tempvlm1));
            }
            
            Value boe_v2 = boe.getOp2();
            VLMContainer tempvlm2 = this.valuemap.get(boe_v2);
            if (tempvlm2 != null) {
                result = result.replace(boe_v2.toString(), transformResult(tempvlm2));
            }
        }
        
        return result;
    }

    @Override
    public String toString() {
        return "ParaContainer [head=" + head + ", valuemap=" + valuemap + "]";
    }

}
