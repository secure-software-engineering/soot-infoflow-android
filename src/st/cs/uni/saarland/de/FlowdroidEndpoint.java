package st.cs.uni.saarland.de;

public class FlowdroidEndpoint {
	private final String method;
	private final String callerMethod;
	
	public FlowdroidEndpoint(String method, String callerMethod){
		this.method = method;
		this.callerMethod = callerMethod;
	}
	
	public String getCallerMethod(){
		return callerMethod;
	}
	
	public String getMethod() {
		return method;
	}

	@Override
	public String toString(){
		return method;
	}
	
	@Override
	public boolean equals(Object toCompare){
		if(!(toCompare instanceof FlowdroidEndpoint)){
			return false;
		}
		FlowdroidEndpoint obj2 = (FlowdroidEndpoint)toCompare;
		if(this.method == null || this.callerMethod == null || obj2.method == null || obj2.callerMethod == null){
			return false;
		}
		return this.method.equals(obj2.method) && this.callerMethod.equals(obj2.callerMethod);
	}
	
	@Override
	public int hashCode(){
		return method.hashCode() ^ callerMethod.hashCode();
	}
}
