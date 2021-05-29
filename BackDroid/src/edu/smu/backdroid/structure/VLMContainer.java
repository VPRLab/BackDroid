package edu.smu.backdroid.structure;

import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;
import soot.SootMethod;
import soot.Value;

import java.util.LinkedList;

/**
 * Value list and method container
 * 
 * @author Daoyuan
 */
public class VLMContainer {
    
    private LinkedList<Value> valuelist;
    
    private SootMethod current_m;
    
    private boolean isFinished;

    public VLMContainer() {
        this.valuelist = new LinkedList<Value>();
        this.isFinished = false;
    }
    
    /**
     * 
     * @param value
     * @param method if null, then do not change SootMethod
     */
    public void addOneValue(Value value, SootMethod method) {
        this.valuelist.add(value);
        
        if (method != null)
            this.current_m = method;
    }

    public LinkedList<Value> getValuelist() {
        return valuelist;
    }

    public void setValuelist(LinkedList<Value> valuelist) {
        this.valuelist = valuelist;
    }

    public SootMethod getCurrentMethod() {
        return current_m;
    }

    public void setCurrentMethod(SootMethod current_m) {
        this.current_m = current_m;
    }
    
    public void recoverToOld(int oldlen, SootMethod old_m) {
        int curlen = this.valuelist.size();
        if (curlen <= oldlen)
            return;
        
        MyUtil.printlnOutput(String.format("oldlen: %s, curlen: %s",
                oldlen, curlen), MyConstant.INFO);
        
        for (int i = oldlen; i < curlen; i++) {
            this.valuelist.remove(oldlen);
        }
        this.current_m = old_m;
    }

//    @Override
//    public String toString() {
//        return "VLMContainer [valuelist=" + valuelist + ", current_m=" + current_m + "]";
//    }

    @Override
    public String toString() {
        return valuelist.toString();
    }

    public boolean getIsFinished() {
        return isFinished;
    }

    public void setIsFinished(boolean isFinished) {
        this.isFinished = isFinished;
    }

}
