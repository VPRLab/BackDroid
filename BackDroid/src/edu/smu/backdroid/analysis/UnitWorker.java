package edu.smu.backdroid.analysis;

import java.util.HashMap;

import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

public class UnitWorker {
    
    private static UnitWorker instance;

    static {
        UnitWorker.instance = new UnitWorker();
    }
    
    private HashMap<Value, Unit> exprTOunit;
    
    public UnitWorker() {
        this.exprTOunit = new HashMap<Value, Unit>();
    }
    
    public void addOneExpr(Value expr, Unit unit) {
        this.exprTOunit.put(expr, unit);
    }
    
    public Unit getOneUnit(Value expr) {
        return this.exprTOunit.get(expr);
    }
    
    /**
     * Get an instance of UnitWorker
     * 
     * @return
     */
    public static UnitWorker v() {
        return UnitWorker.instance;
    }
    
    /**
     * get an InvokeExpr from a Unit
     * 
     * @param unit
     * @return InvokeExpr or null
     */
    public InvokeExpr getInvokeExpr(Unit unit) {
        if (unit == null)
            return null;
        
        InvokeExpr invokeexpr = null;
        
        if (unit instanceof InvokeStmt) {
            InvokeStmt invokestmt = (InvokeStmt) unit;
            invokeexpr = invokestmt.getInvokeExpr();
            
        } else if (unit instanceof AssignStmt) {
            AssignStmt as = (AssignStmt) unit;
            Value v = as.getRightOp();

            if (as.containsInvokeExpr()) {
                invokeexpr = (InvokeExpr) v;
            }
        }
        
        return invokeexpr;
    }
    
    /**
     * Whether do we further a value
     * 
     * @param value
     * @return false: not trace; true: trace
     */
    public boolean isTraceThisValue(Value value) {
        if (value == null)
            return false;
        
        //TODO any other case?
        //TODO the InvokeExpr case, the field case, the object case
        // NullConstant is also a constant
        if (value instanceof Constant)
            return false;
        
        return true;
    }

}
