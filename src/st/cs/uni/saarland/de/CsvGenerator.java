package st.cs.uni.saarland.de;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import com.thoughtworks.xstream.XStream;

import au.com.bytecode.opencsv.CSVWriter;

public class CsvGenerator {
	
	public static void main(String[] args){
		if(args.length < 4){
			System.err.println("Usage: \n -maliciousDir\n -benignDir");
			return;
		}
		String maliciousDir = "";
		String benignDir = "";
		String csvName = "mudflow_results.csv";
		boolean api = false;
		for(int i=0; i < args.length; i++){
			String arg = args[i];
			if(arg.equalsIgnoreCase("-maliciousDir")){
				maliciousDir = args[++i];
			}
			else if(arg.equalsIgnoreCase("-benignDir")){
				benignDir = args[++i];
			}
			else if(arg.equalsIgnoreCase("-csvName")){
				csvName = args[++i];
			}
			else if(arg.equalsIgnoreCase("-api")){
				api = true;
			}
		}
		
		if(benignDir.isEmpty() || maliciousDir.isEmpty()){
			System.err.println("Usage: \n -maliciousDir\n -benignDir");
			return;
		}
		
		Map<AppInfo, Set<FlowdroidResults>> flowDroidResults = new HashMap<>();
		
		flowDroidResults.putAll(processDir(benignDir, false));
		flowDroidResults.putAll(processDir(maliciousDir, true));
				
		saveToCsv(csvName, flowDroidResults, api);
		
		System.out.println("Done");
		
	}
	
	private static void saveToCsv(String fileName, Map<AppInfo, Set<FlowdroidResults>> results, boolean api){
		try {
			CSVWriter csvWriter = new CSVWriter(new FileWriter(fileName), ';');
			Set<String> header = new HashSet<>();
			if(api){
				results.values().forEach(resInApp->{
					header.addAll(resInApp.stream().map(x->x.getSource().getMethod()).collect(Collectors.toSet()));
					header.addAll(resInApp.stream().map(x->x.getSink().getMethod()).collect(Collectors.toSet()));
				});
				
				header.remove("NO_SENSITIVE_SOURCE");
				header.remove("NO_SENSITIVE_SINK");
				
				System.out.println(String.format("Found %s distinct apis", header.size()));
			}
			else{
				results.values().forEach(resInApp->{
					header.addAll(resInApp.stream().map(x->x.toString()).collect(Collectors.toSet()));
				});
				
				System.out.println(String.format("Found %s distinct data flows", header.size()));
			}
			
			List<String> headerList = new ArrayList<>();
			headerList.add("name");
			headerList.add("malicious");
			headerList.addAll(header);
			String[] headerLine  = new String[headerList.size()];
			csvWriter.writeNext(headerList.toArray(headerLine));
			
			composeRowForApk(results, csvWriter, headerLine, api);
			
			csvWriter.close();

			System.out.println("Results saved to "+ fileName);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static void composeRowForApk(Map<AppInfo, Set<FlowdroidResults>> results, CSVWriter csvWriter,
			String[] headerLine, boolean api) {
		final int appsCount = results.size();
		AtomicInteger currentApp = new AtomicInteger(0);
		results.keySet().forEach(appInfo ->{
			System.out.println(String.format("Composing a row for an app %s out of %s", currentApp.incrementAndGet(), appsCount));
			String[] row = new String[headerLine.length];
			Set<String> flows = new HashSet<>();
			if(api){
				flows.addAll(results.get(appInfo).stream().map(x->x.getSource().getMethod()).collect(Collectors.toSet()));
				flows.addAll(results.get(appInfo).stream().map(x->x.getSink().getMethod()).collect(Collectors.toSet()));
			}
			else{
				flows = results.get(appInfo).stream().map(x->x.toString()).collect(Collectors.toSet());
			}
			int counter = 0;
			row[counter++] = appInfo.getApkName();
			row[counter++] = appInfo.IsMalicious() ? "1" : "0";
			
			while(counter < row.length){
				
				String flow = headerLine[counter];
				row[counter] = flows.contains(flow) ? "1" : "0";
				
				counter++;
			}
			csvWriter.writeNext(row);
		});
	}
	
	private static Map<AppInfo, Set<FlowdroidResults>> processDir(String dir, boolean isMalicious){
		File processedDir = new File(dir);
		Map<AppInfo, Set<FlowdroidResults>> resultsForDir = new HashMap<>();
		
		if(dir != null && processedDir.exists()){
			for(File apk : processedDir.listFiles()){
				resultsForDir.putAll(processFile(apk, isMalicious));
			}
		}
		
		return resultsForDir;
	}
	
	private static Map<AppInfo, Set<FlowdroidResults>> processFile(File file, boolean isMalicious){
		if(file != null && file.getName().endsWith(".xml")){
			System.out.println("Processing " + file.getName());
			XStream xStream = new XStream();
			xStream.processAnnotations(FlowdroidResults.class);
			xStream.processAnnotations(FlowdroidEndpoint.class);
			xStream.setMode(XStream.NO_REFERENCES);
			@SuppressWarnings("unchecked")
			List<FlowdroidResults> results = (List<FlowdroidResults>)xStream.fromXML(file);
			ListIterator<FlowdroidResults> iter = results.listIterator();
			while(iter.hasNext()){
				FlowdroidResults x = iter.next();
				FlowdroidEndpoint source = x.getSource();
				FlowdroidEndpoint sink = x.getSink();
				
				if(source.getMethod().contains("SharedPreferences")){
					source = new FlowdroidEndpoint("SHARED_PREFERENCES", source.getCallerMethod());
				}
				else if(source.getMethod().contains("android.util.Log")){
					source = new FlowdroidEndpoint("LOG", source.getCallerMethod());
				}
				
				if(sink.getMethod().contains("android.util.Log")){
					sink = new FlowdroidEndpoint("LOG", sink.getCallerMethod());
				}
				else if(sink.getMethod().contains("SharedPreferences")){
					sink = new FlowdroidEndpoint("SHARED_PREFERENCES", sink.getCallerMethod());
				}
				iter.remove();
				iter.add(new FlowdroidResults(source, sink));
			}
			
			AppInfo info = new AppInfo(file.getName().replace("_results.xml", ".apk"), isMalicious);
			HashMap<AppInfo, Set<FlowdroidResults>> res = new HashMap<>();
			res.put(info, new HashSet<>(results));
			return res;
		}
		return new HashMap<>();
	}

}
