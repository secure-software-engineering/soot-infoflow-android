package st.cs.uni.saarland.de;

public class FlowdroidResults {
	private final FlowdroidEndpoint source;
	public FlowdroidEndpoint getSource() {
		return source;
	}

	private final FlowdroidEndpoint sink;
	
	public FlowdroidEndpoint getSink() {
		return sink;
	}

	public FlowdroidResults(FlowdroidEndpoint source, FlowdroidEndpoint sink){
		this.source = source;
		this.sink = sink;
	}
	
	@Override
	public String toString(){
		return String.format("%s -> %s", source, sink);
	}
	
	@Override
	public int hashCode(){
		return source.hashCode() ^ sink.hashCode();
	}
	
	@Override
	public boolean equals(Object toCompare){
		if(!(toCompare instanceof FlowdroidResults)){
			return false;
		}		
		FlowdroidResults obj2 = (FlowdroidResults)toCompare;
		if(this.source == null || this.sink == null || obj2.source == null || obj2.sink == null){
			return false;
		}
		return this.source.equals(obj2.source) && this.sink.equals(obj2.sink);
	}
}
