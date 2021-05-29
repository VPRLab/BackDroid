package edu.smu.backdroid.graph;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import soot.util.dot.DotGraph;
import soot.util.dot.DotGraphConstants;
import soot.util.dot.DotGraphEdge;
import soot.util.dot.DotGraphNode;

/**
 * Convert BDG to DotGraph
 * 
 * @author Daoyuan
 * @since 13-04-09
 * @restart 17-06-06
 * @see CFGToDotGraph
 */
public class BDGToDotGraph {
    
    public final static int LEN_EACH_LINE = 20;
    
    /**
     * connect method and its unit
     */
    public final static String CONNECTOR = "--";
    
    /**
     * prefix for subgraph cluster
     */
    public final static String CLUSTER = "cluster_";

    public BDGToDotGraph() {
    }
    
    public DotGraph drawBDG(BDG bdg, String graphname) {
        DotGraph canvas = initDotGraph(bdg, graphname);
        
        // Draw the field nodes first
        drawAllEdgeAndNode(canvas, bdg, true);
        setSubGraphandNodeLabel(canvas, bdg, true);
        
        // Then draw the normal nodes
        drawAllEdgeAndNode(canvas, bdg, false);
        setSubGraphandNodeLabel(canvas, bdg, false);
        
        return canvas;
    }
    
    private DotGraph initDotGraph(BDG bdg, String graphname) {
        DotGraph canvas = new DotGraph(graphname);
        
        //canvas.setPageSize(8.5, 11.0); //will become several pages
        // A4   210*297     8-1/4*11-3/4 
        //canvas.setGraphSize(11.0, 8.5); //reverse it
        canvas.setGraphLabel(graphname);
        canvas.setNodeShape(DotGraphConstants.NODE_SHAPE_BOX);
        //canvas.setGraphAttribute("size", "\"7.5,11\"");
        //canvas.setGraphAttribute("ratio", "fill");
        
        return canvas;
    }
    
    /**
     * Draw all edges and their nodes.
     * Each node use full name, but label use its own short string.
     * 
     * Note that canvas.drawEdge() will also draw the nodes.
     * 
     * @param canvas
     * @param bdg
     */
    private void drawAllEdgeAndNode(DotGraph canvas, BDG bdg,
            final boolean isStaticTrack) {
        
        Iterator<BDGEdge> iter_e = bdg.edgeIterator(isStaticTrack);
        
        while (iter_e.hasNext()) {
            BDGEdge edge = iter_e.next();
            BDGUnit src_node = edge.getSource();
            BDGUnit tgt_node = edge.getTarget();
            
            String src_msig = src_node.getMSig();
            String tgt_msig = tgt_node.getMSig();
            int src_id = src_node.getDrawId();
            int tgt_id = tgt_node.getDrawId();
            
            // label for display
            String src_label = src_node.getUnitStr();
            String tgt_label = tgt_node.getUnitStr();
            // name for identity
            String src_name = src_msig + CONNECTOR + src_label + src_id;
            String tgt_name = tgt_msig + CONNECTOR + tgt_label + tgt_id;
            
            DotGraphEdge dotedge = canvas.drawEdge(src_name, tgt_name);
            
            // set edge type
            int edgetype = edge.getType();
            switch (edgetype) {
                case BDGEdgeType.DIRECT_EDGE:
                    dotedge.setAttribute("color", "black");
                    break;
                case BDGEdgeType.CROSS_EDGE:
                    dotedge.setAttribute("color", "blue");
                    dotedge.setAttribute("style", DotGraphConstants.EDGE_STYLE_DOTTED);
                    break;
                case BDGEdgeType.RETURN_EDGE:
                    dotedge.setAttribute("color", "red");
                    dotedge.setAttribute("style", DotGraphConstants.EDGE_STYLE_DOTTED);
                    break;
                default:
                    dotedge.setAttribute("color", "red");
                    break;
            }
        }
    }
    
    /**
     * set each subgraph, and set label for each node
     * 
     * @param canvas
     * @param bdg
     */
    private void setSubGraphandNodeLabel(DotGraph canvas, BDG bdg,
            final boolean isStaticTrack) {
        
        Map<String, List<BDGUnit>> nodesetMap = bdg.getNodeListMap(isStaticTrack);
        
        BDGUnit initNode = null;
        if (!isStaticTrack)
            initNode = bdg.getInitNode();
        
        List<BDGUnit> fieldTails = null;
        Set<BDGUnit> normalTails = null;
        Set<BDGUnit> fakeTails = null;
        if (isStaticTrack)
            fieldTails = bdg.getFieldTails();
        else {
            normalTails = bdg.getNormalTails();
            fakeTails = bdg.getFakeTails();
        }
        
        Set<String> keyset = nodesetMap.keySet();
        for (String str_m : keyset) {
            String str_cluster = CLUSTER + str_m;
            DotGraph subgraph = canvas.createSubGraph(str_cluster);
            subgraph.setGraphLabel(str_m);
            
            List<BDGUnit> nodes = nodesetMap.get(str_m);
            for (BDGUnit node : nodes) {
                String str_u = node.getUnitStr();
                String str_name = str_m + CONNECTOR + str_u + node.getDrawId();
                
                DotGraphNode subnode = subgraph.drawNode(str_name);
                subnode.setLabel(str_u);
                /*
                 * Make a color for the init node
                 * Here simply compare string to determine whether it is the init node
                 * 
                 * See
                 * http://www.graphviz.org/doc/info/attrs.html
                 * http://www.graphviz.org/doc/info/colors.html
                 */
                if (initNode != null && initNode.equals(node)) {
                    subnode.setAttribute("style", DotGraphConstants.NODE_STYLE_FILLED);
                    subnode.setAttribute("fillcolor", "aquamarine");
                }
                else if ((normalTails != null && normalTails.contains(node))
                        || (fieldTails != null && fieldTails.contains(node))) {
                    subnode.setAttribute("style", DotGraphConstants.NODE_STYLE_FILLED);
                }
                else if (fakeTails != null && fakeTails.contains(node)) {
                    subnode.setAttribute("style", DotGraphConstants.NODE_STYLE_FILLED);
                    subnode.setAttribute("fillcolor", "antiquewhite");
                }
            }
        }
    }

}
