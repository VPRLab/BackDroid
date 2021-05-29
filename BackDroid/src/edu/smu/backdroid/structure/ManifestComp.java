package edu.smu.backdroid.structure;

import java.util.HashSet;
import java.util.Set;

public class ManifestComp {
    
    private int type;
    
    private String name;
    
    private Set<String> action_set;

    public ManifestComp(int type, String name) {
        this.type = type;
        this.name = name;
        this.action_set = null;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
    
    /**
     * Must be checked before calling getActions()
     * @return
     */
    public boolean hasAction() {
        if (action_set == null)
            return false;
        else if (action_set.isEmpty())
            return false;
        else
            return true;
    }

    public Set<String> getActions() {
        return action_set;
    }

    public void addAction(String action) {
        if (action_set == null)
            action_set = new HashSet<String>();
        
        action_set.add(action);
    }

    @Override
    public String toString() {
        if (hasAction())
            return "ManifestComp [type=" + type + ", name=" + name + ", action_set=" + action_set + "]";
        else
            return "ManifestComp [type=" + type + ", name=" + name + "]";
    }

}
