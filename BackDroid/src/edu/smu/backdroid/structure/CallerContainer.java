package edu.smu.backdroid.structure;

import soot.SootMethod;
import soot.Unit;

/**
 * 
 * @author Daoyuan
 * @since Nov 7, 2017
 */
public class CallerContainer {
    
    private Unit src_unit;
    
    private SootMethod src_method;
    
    private CallerContainer next;

    public CallerContainer(Unit src_unit, SootMethod src_method) {
        this.src_unit = src_unit;
        this.src_method = src_method;
        this.next = null;
    }
    
    public boolean hasNextContainer() {
        if (next == null)
            return false;
        else
            return true;
    }
    
    public void addNextContainer(CallerContainer next) {
        this.next = next;
    }
    
    public CallerContainer getNextContainer() {
        return next;
    }

    public Unit getSrcUnit() {
        return src_unit;
    }

    public void setSrcUnit(Unit src_unit) {
        this.src_unit = src_unit;
    }

    public SootMethod getSrcMethod() {
        return src_method;
    }

    public void setSrcMethod(SootMethod src_method) {
        this.src_method = src_method;
    }
    
    /**
     * We use the string for comparison
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((src_method == null) ? 0 : src_method.getSignature().hashCode());
        result = prime * result + ((src_unit == null) ? 0 : src_unit.toString().hashCode());
        return result;
    }

    /**
     * We use the string for comparison
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CallerContainer other = (CallerContainer) obj;
        if (src_method == null) {
            if (other.src_method != null)
                return false;
        } else if (!src_method.getSignature().equals(other.src_method.getSignature()))
            return false;
        if (src_unit == null) {
            if (other.src_unit != null)
                return false;
        } else if (!src_unit.toString().equals(other.src_unit.toString()))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return src_method.getSignature();
    }

}
