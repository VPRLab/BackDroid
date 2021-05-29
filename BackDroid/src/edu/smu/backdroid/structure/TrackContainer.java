package edu.smu.backdroid.structure;

import soot.SootMethod;
import soot.Value;

import java.util.ArrayList;
import java.util.List;

public class TrackContainer {
    
    /**
     * the default value is false
     */
    private boolean isUntraceable;
    
    /**
     * one of the ServerSocket constructor methods
     * @see edu.smu.backdroid.util.MyConstant
     */
    private String methodSig;
    
    /**
     * might be 8090, or an expression like "getRandom()%1000 + 800"
     * 
     * for the index later
     */
    private String port;
    
    /**
     * The parameter list.
     * 
     * In the beginning, all are working list;
     * In the end, all will become the done list.
     */
    private List<ParaContainer> workList;
    
    public TrackContainer(String methodSig) {
        this.isUntraceable = false;
        this.methodSig = methodSig;
        analyzeMethodSig(methodSig);
    }

    /**
     * finish the remaining initialization by analyzing method signature
     * 
     * @param methodSig
     */
    private void analyzeMethodSig(String methodSig) {
        this.workList = new ArrayList<ParaContainer>();
        
        //
        // http://stackoverflow.com/a/13948789/197165
        // Output: "int,int"
        //
        String[] paratypes = methodSig.split(" ")[2].split("\\(")[1].split("\\)")[0].split(",");
        
        int i = 0;
        for (String paratype : paratypes) {
            ParaHead parahead = new ParaHead(i, paratype);
            ParaContainer paracontainer = new ParaContainer(parahead);
            this.workList.add(paracontainer);
            
            i++;
        }
    }
    
    /**
     * add tainted value into a parameter map specified by index
     * 
     * @param index
     * @param value
     */
    public void addInitTaintValue(int index, Value value, SootMethod method) {
        ParaContainer paracontainer = this.workList.get(index);
        this.addInitTaintValue(paracontainer, value, method);
    }
    
    /**
     * add tainted value into a parameter map specified by ParaContainer
     * 
     * @param paracontainer
     * @param value
     */
    public void addInitTaintValue(ParaContainer paracontainer, Value value, SootMethod method) {
        paracontainer.addInitTaintValue(value, method);
    }
    
    public List<ParaContainer> getParaContainers() {
        return this.workList;
    }
    
    public boolean getIsFinished() {
        boolean result = true;
        
        for (ParaContainer pc : this.workList) {
            if (!pc.getIsFinished()) {
                result = false;
                break;
            }
        }
        
        return result;
    }

    @Override
    public String toString() {
        return "TrackContainer [methodSig=" + methodSig + ", port=" + port + ", workList="
                + workList + "]";
    }

    public String getMethodSig() {
        return methodSig;
    }

    public void setMethodSig(String methodSig) {
        this.methodSig = methodSig;
    }

    public boolean isUntraceable() {
        return isUntraceable;
    }

    public void setUntraceable(boolean isUntraceable) {
        this.isUntraceable = isUntraceable;
    }

}
