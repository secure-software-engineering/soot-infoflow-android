package st.cs.uni.saarland.de;

public class CONTENT_RESOLVER_CONSTANTS {
	public final static String QUERY="<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>";
	public final static String INSERT="<android.content.ContentResolver: android.net.Uri insert(android.net.Uri,android.content.ContentValues)>";
	public final static String BULKINSERT="<android.content.ContentResolver: int bulkInsert(android.net.Uri,android.content.ContentValues[])>";
	public final static String DELETE="<android.content.ContentResolver: int delete(android.net.Uri,java.lang.String,java.lang.String[])>";
	public final static String UPDATE="<android.content.ContentResolver: int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])>";
	public final static String PARSE_URI="<android.net.Uri: android.net.Uri parse(java.lang.String)>";
	
	public final static String GET_STRING="<android.database.Cursor: java.lang.String getString(int)>";
	public final static String GET_LONG="<android.database.Cursor: long getLong(int)>";
	public final static String GET_INT="<android.database.Cursor: int getInt(int)>";
	public final static String GET_BLOB="<android.database.Cursor: byte[] getBlob(int)>";
	public final static String GET_TYPE="<android.database.Cursor: int getType(int)>";
	public final static String GET_COLUMN_NAMES="<android.database.Cursor: java.lang.String[] getColumnNames()>";
	public final static String GET_COLUMN_NAME="<android.database.Cursor: java.lang.String getColumnName(int)>";	
}
