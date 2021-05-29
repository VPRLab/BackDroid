package edu.smu.backdroid.structure;

import soot.Value;

public class TaintContainer {
    
    private Value index;
    
    private Value taint;

    public TaintContainer(Value index, Value taint) {
        this.index = index;
        this.taint = taint;
    }

    public Value getIndex() {
        return index;
    }

    public void setIndex(Value index) {
        this.index = index;
    }

    public Value getTaint() {
        return taint;
    }

    public void setTaint(Value taint) {
        this.taint = taint;
    }

    @Override
    public String toString() {
        return "TaintContainer [index=" + index + ", taint=" + taint + "]";
    }

}
