package st.cs.uni.saarland.de;

public class AppInfo {
	private final String apkName;
	
	public String getApkName() {
		return apkName;
	}

	public Boolean IsMalicious() {
		return isMalicious;
	}

	private final Boolean isMalicious;
	
	public AppInfo(String apkName, Boolean isMalicious){
		this.apkName = apkName;
		this.isMalicious = isMalicious;
	}
	
	@Override
	public boolean equals(Object obj){
		if(!(obj instanceof AppInfo)){
			return false;
		}
		AppInfo toCompare = (AppInfo)obj;
		if(this.apkName == null || toCompare.apkName == null){
			return false;
		}
		return this.apkName.equals(toCompare.apkName) && this.isMalicious.equals(toCompare.isMalicious);
	}
	
	@Override
	public int hashCode(){
		return this.apkName.hashCode() ^ this.isMalicious.hashCode();
	}
}
