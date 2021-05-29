package edu.smu.backdroid.analysis;

import java.util.Iterator;
import java.util.List;

import soot.Body;
import soot.PatchingChain;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.InvokeExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import edu.smu.backdroid.PortDetector;
import edu.smu.backdroid.structure.TrackContainer;
import edu.smu.backdroid.util.MyConstant;
import edu.smu.backdroid.util.MyUtil;

/**
 * @author Daoyuan
 * @deprecated
 */
public class SummaryWorker {
    
    private static SummaryWorker instance;
    
    static {
        SummaryWorker.instance = new SummaryWorker();
    }
    
    public SummaryWorker() {
    }
    
    /**
     * Get an instance of SummaryWorker
     * 
     * @return
     */
    public static SummaryWorker v() {
        return SummaryWorker.instance;
    }
    
    /**
     * Taint the summary of InvokeExpr *along the way*
     * 
     * InvokeExpr can be from:
     * 1) DefinitionStmt
     * -- $i0 = staticinvoke <com.kugou.framework.e.b.b.a: int c()>();
     * -- $i1 = virtualinvoke r3.<xcxin.filexpert.settings.i: int J()>();
     * -- $i1 = staticinvoke <com.afollestad.neuron.Terminal: int access$000(com.afollestad.neuron.Terminal)>($r5);
     * 2) InvokeStmt
     * -- specialinvoke $r8.<java.net.InetSocketAddress: void <init>(java.lang.String,int)>($r9, $i0);
     * -- virtualinvoke $r6.<org.teleal.cling.transport.impl.apache.StreamServerConfigurationImpl: int getListenPort()>()
     * 
     * @param track TrackContainer
     * @param ie InvokeExpr
     * @param unit Unit that is corresponding to InvokeExpr
     * @deprecated
     */
    public void taintSummaryForInvokeExpr(
            TrackContainer track,
            InvokeExpr ie, Unit unit, Value thisvar, List<Value> paras) {
        
        CallGraph cg = ClassWorker.getCallGraph();
        Iterator<Edge> edges = cg.edgesOutOf(unit);
        
        while (edges.hasNext()) {   //TODO we should have too many edges
            Edge edge = edges.next();
            SootMethod tgt_method = edge.tgt();
            String tgt_method_sig = tgt_method.getSignature();
            MyUtil.printlnOutput("==> "+tgt_method_sig, MyConstant.DEBUG);
            
            //
            // TODO filter non-app class
            // e.g., java.util.AbstractMap$SimpleEntry
            //
            // TODO will API functions be jumped?
            //
            String tgt_classname = tgt_method.getDeclaringClass().getName();
            if (PortDetector.apiClassSet.contains(tgt_classname))
                continue;
            
            //
            // Summarize the return value
            //
            MyUtil.printlnOutput(String.format("--> Summarizing InvokeExpr Return: %s", tgt_method_sig),
                    MyConstant.DEBUG);
            Body tgt_body = MyUtil.retrieveActiveSSABody(tgt_method);
            PatchingChain<Unit> tgt_u_chain = tgt_body.getUnits();
            Unit tgt_last_unit = tgt_u_chain.getLast();
            
            if (tgt_last_unit instanceof ReturnStmt) {
//                ReturnStmt tgt_rs = (ReturnStmt)tgt_last_unit;
//                Value tgt_rs_value = tgt_rs.getOp();
//                
//                pc.addTaintValue(index, tgt_rs_value, tgt_method); //no split here                         
//                boolean isTainted = MethodWorker.v().backwardUnit(tgt_last_unit, tgt_u_chain, track, index);
//                
//                if (isTainted) {
//                    furtherCheck(track);
//                    break;  //TODO only handle one flow???
//                    
//                } else {
//                    continue;
//                }
            }
            else {
                MyUtil.printlnOutput(String.format("%s The last unit is not a return stmt", 
                        MyConstant.CriticalPrefix), MyConstant.RELEASE);
            }
        }
    }

}
