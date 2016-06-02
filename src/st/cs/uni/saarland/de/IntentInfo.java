package st.cs.uni.saarland.de;

import java.util.HashSet;
import java.util.Set;

public class IntentInfo extends FlowdroidEndpoint{
	public IntentInfo(String method, String callerMethod){
		super(method, callerMethod);
        this.extras = new HashSet<>();
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
    	if(className != null && className.contains("/")){
    		className = className.replace("/", ".");
    	}
        this.className = className;
    }

    private String className;

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    private String data;

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    private String action;

    public Set<String> getExtras() {
        return extras;
    }

    public void addExtra(String extra) {
        this.extras.add(extra);
    }

    private Set<String> extras;
    
    @Override
    public String toString(){
    	if(className != null){
    		return "EXPLICIT_INTENT";
    	}
    	if(action != null && (action.startsWith("android.") || action.contains(".android."))){
    		if(data != null && data.contains(":")){
    			return String.format("IMPLICIT_INTENT:%s:%s", action, data.split(":")[0]);
    		}
    		return String.format("IMPLICIT_INTENT:%s", action);
    	}
    	return "IMPLICIT_INTENT";
    }
}
