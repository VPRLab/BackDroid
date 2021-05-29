package edu.smu.backdroid.structure;

public class ParaHead {
    
    /**
     * the index of this parameter in a method
     */
    private int index;
    
    /**
     * the parameter type in String
     */
    private String type;
    
    /**
     * is this a class object type?
     * True: yes
     * TODO seems no use
     */
    private boolean isObject;
    
    /**
     * is the analysis of this parameter finished?
     * False: no
     */
    private boolean isFinished;
    
    public ParaHead(int index, String type) {
        this.index = index;
        this.type = type;
        this.isFinished = false;
        
        /*
         * TODO current type determination is very naive
         */
        if (type.equals("int"))
            this.isObject = false;
        else
            this.isObject = true;
    }
    
    public boolean getIsFinished() {
        return isFinished;
    }
    
    public void setIsFinished(boolean isFinished) {
        this.isFinished = isFinished;
    }

    @Override
    public String toString() {
        return "ParaHead [index=" + index + ", type=" + type + ", isObject=" + isObject
                + ", isFinished=" + isFinished + "]";
    }
    
}
