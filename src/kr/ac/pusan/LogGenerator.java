/**
 * 
 */
package kr.ac.pusan;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.deckfour.xes.classification.XEventAttributeClassifier;
import org.deckfour.xes.extension.std.XConceptExtension;
import org.deckfour.xes.extension.std.XLifecycleExtension;
import org.deckfour.xes.extension.std.XOrganizationalExtension;
import org.deckfour.xes.extension.std.XSoftwareEventExtension;
import org.deckfour.xes.extension.std.XTimeExtension;
import org.deckfour.xes.factory.XFactory;
import org.deckfour.xes.factory.XFactoryNaiveImpl;
import org.deckfour.xes.model.XAttribute;
import org.deckfour.xes.model.XAttributeMap;
import org.deckfour.xes.model.XEvent;
import org.deckfour.xes.model.XLog;
import org.deckfour.xes.model.XTrace;
import org.deckfour.xes.out.XesXmlSerializer;

/**
 * This program reads a software event log and converts it into an XES-compliant 
 * event log. The Software Event Extension is an extension provided by the OpenXES 
 * and it is used to map function calls into a series of events.
 * 
 * @author natan
 */
public class LogGenerator {
	
	@SuppressWarnings("unused")
	private static Path filepath;
	
	@SuppressWarnings("unused")
	private static Properties props;

	/**
	 * The main entry of the program.
	 * 
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		
		// Application level properties.
		props = getProperties("conf/application.properties");
		
		// Instantiate the XES factory object.
		XFactory factory = new XFactoryNaiveImpl();
		
		// Log mapping definition.
		Properties mapping = getProperties("conf/mapping.properties");
		
		// Construct an XLog object.
		XLog log = factory.createLog();
		
		// Use extensions.
		log.getExtensions().add(XConceptExtension.instance());
		log.getExtensions().add(XLifecycleExtension.instance());
		log.getExtensions().add(XOrganizationalExtension.instance());
		log.getExtensions().add(XSoftwareEventExtension.instance());
		log.getExtensions().add(XTimeExtension.instance());
		
		// Adding classifiers.
		Arrays.asList(
				new XEventAttributeClassifier("Event Name", 
						XConceptExtension.KEY_NAME),
				new XEventAttributeClassifier("(Event Name AND Lifecycle transition)", 
						XConceptExtension.KEY_NAME, 
						XLifecycleExtension.KEY_TRANSITION),
				new XEventAttributeClassifier("Callee Name", 
						XConceptExtension.KEY_NAME),
				new XEventAttributeClassifier("Callee Joinpoint", 
						XConceptExtension.KEY_NAME, 
						XSoftwareEventExtension.KEY_CALLEE_LINENR),
				new XEventAttributeClassifier("(Callee Joinpoint AND Software Event Type)", 
						XSoftwareEventExtension.KEY_TYPE, 
						XConceptExtension.KEY_NAME, 
						XSoftwareEventExtension.KEY_CALLEE_LINENR)
				).stream()
					.forEach(log.getClassifiers()::add);
		
		// Construct top-level metadata to the event log.
		XAttributeMap metadata = factory.createAttributeMap();
		
		// -- Author information.
		Arrays.asList(
				factory.createAttributeLiteral("Author", 
						(String) props.get("author.name"), 
						XConceptExtension.instance()), 
				factory.createAttributeLiteral("Affiliation", 
						(String) props.get("author.affiliation"), 
						XConceptExtension.instance()),
				factory.createAttributeLiteral("Contact", 
						(String) props.get("author.contact"),
						XConceptExtension.instance())
				).stream()
					.forEach(attribute -> metadata.put(attribute.getKey(), attribute));
		
		// -- Log level software event attributes.
		Arrays.asList(
				factory.createAttributeBoolean(XSoftwareEventExtension.KEY_HAS_DATA, 
						Boolean.parseBoolean( (String) mapping.get("log.hasData") ), 
						XSoftwareEventExtension.instance()),
				factory.createAttributeBoolean(XSoftwareEventExtension.KEY_HAS_EXCEPTION, 
						Boolean.parseBoolean( (String) mapping.get("log.hasException") ), 
						XSoftwareEventExtension.instance())
				).stream()
					.forEach(attribute -> metadata.put(attribute.getKey(), attribute));
		
		log.setAttributes(metadata); // Write the metadata to the log object.
		
		// Assume that there is only a single trace object.
		XTrace trace = factory.createTrace();
		
		filepath = new File(args[0]).toPath(); // The path pointed to the file location.
		
		Supplier<Stream<List<String>>> csv = () -> {
			try {
				return Files.readAllLines(filepath, StandardCharsets.UTF_8)
						.stream()
							.map(row -> row.replace("\"", ""))
							.map(row -> Arrays.asList(row.split(",")));
			} catch (IOException e) {
				// Print the error stack trace.
				e.printStackTrace();
			}
			return null;
		};
		
		// Extract header from loaded files.
		Optional<List<String>> header = csv.get().findFirst();
		
		// Adding events to trace.
		csv.get().skip(1)
				.map(row -> asEvent(factory, header.get(), row, mapping))
				.forEach(row -> trace.add(row));
		
		log.add(trace);
		
		// Serialize the log object to XES file.
		XesXmlSerializer serializer = new XesXmlSerializer();
		
		filepath = new File(args[1]).toPath();

		serializer.serialize(log, new FileOutputStream(filepath.toString()));
	}

	private static XEvent asEvent(XFactory factory, List<String> header, List<String> row, Properties mapping) {

		Map<String, String> cols = Arrays.asList(
				List.of(XConceptExtension.KEY_NAME, 
						(String) mapping.get("event.conceptName")),
				List.of(XSoftwareEventExtension.KEY_TYPE, 
						(String) mapping.get("event.type")),
				List.of(XSoftwareEventExtension.KEY_CALLEE_PACKAGE, 
						(String) mapping.get("event.package")),
				List.of(XSoftwareEventExtension.KEY_CALLEE_CLASS, 
						(String) mapping.get("event.class")),
				List.of(XSoftwareEventExtension.KEY_CALLEE_METHOD, 
						(String) mapping.get("event.method")),
				List.of(XSoftwareEventExtension.KEY_CALLEE_PARAMSIG, 
						(String) mapping.get("event.paramSig")),
				List.of(XSoftwareEventExtension.KEY_CALLEE_RETURNSIG, 
						(String) mapping.get("event.returnSig")),
				List.of(XSoftwareEventExtension.KEY_CALLEE_ISCONSTRUCTOR, 
						(String) mapping.get("event.isConstructor")),
				List.of(XSoftwareEventExtension.KEY_CALLEE_INSTANCEID, 
						(String) mapping.get("event.instanceId")),
				List.of(XSoftwareEventExtension.KEY_CALLEE_FILENAME, 
						(String) mapping.get("event.filename")),
				List.of(XSoftwareEventExtension.KEY_CALLEE_LINENR, 
						(String) mapping.get("event.lineNr")),
				List.of(XSoftwareEventExtension.KEY_RETURN_VALUE, 
						(String) mapping.get("event.returnValue")),
				List.of(XSoftwareEventExtension.KEY_PARAMS, 
						(String) mapping.get("event.params")),
				List.of(XSoftwareEventExtension.KEY_APP_NAME, 
						(String) mapping.get("event.appName")),
				List.of(XSoftwareEventExtension.KEY_APP_TIER, 
						(String) mapping.get("event.appTier")),
				List.of(XSoftwareEventExtension.KEY_APP_NODE, 
						(String) mapping.get("event.appNode")),
				List.of(XSoftwareEventExtension.KEY_APP_SESSION, 
						(String) mapping.get("event.appSession")),
				List.of(XSoftwareEventExtension.KEY_THREAD_ID, 
						(String) mapping.get("event.threadId")),
				List.of(XSoftwareEventExtension.KEY_NANOTIME, 
						(String) mapping.get("event.nanotime")),
				List.of(XSoftwareEventExtension.KEY_EX_THROWN, 
						(String) mapping.get("event.exThrown")),
				List.of(XSoftwareEventExtension.KEY_EX_CAUGHT, 
						(String) mapping.get("event.exCaught"))
				).stream()
					.filter(col -> !col.get(1).equals(""))		
					.collect(Collectors.toMap(
							col -> (String) col.get(0), 			
							col -> (String) col.get(1)));
		
		Map<String, XAttribute> standardAttribute = header.stream()
				.filter(col -> !cols.containsValue(col))
				.collect(Collectors.toMap(Function.identity(), 
						(col) -> toXAttribute(factory, col, row.get(header.indexOf(col)))));
		
		Map<String, XAttribute> attribute = cols.entrySet()
				.stream()
					.peek(col -> col.setValue(row.get(header.indexOf(col.getValue()))))
					.collect(Collectors.toMap(Map.Entry::getKey,
							e -> toXAttribute(factory, e.getKey(), e.getValue())));
		
		XAttributeMap eventAttribute = factory.createAttributeMap();
		
		XEvent event = factory.createEvent();
		
		eventAttribute.putAll(standardAttribute);
		
		eventAttribute.putAll(attribute);
		
		event.setAttributes(eventAttribute);
		
		return event;
	}

	private static XAttribute toXAttribute(XFactory factory, String key, String value) {
		XAttribute attr;
		value = value == "" ? "novalue" : value;
		if (StringUtils.isNumeric(value)) {
			if (value.matches("[0-9]*\\.[0-9]*")) {
				double val = Double.parseDouble(value);
				attr = factory.createAttributeContinuous(key, val, null);
				return attr;
			} else if (value.matches("[0-9]*")) {
				long val = Long.parseLong(value);
				attr = factory.createAttributeDiscrete(key, val, null);
				return attr;
			}
		} else if ("true".equals(value.toLowerCase()) 
				|| "false".equals(value.toLowerCase())) {
			boolean val = Boolean.parseBoolean(value.toLowerCase());
			attr = factory.createAttributeBoolean(key, val, null);
			return attr;
		} else {
			attr = factory.createAttributeLiteral(key, value, null);
			return attr;
		}
		key = null; value = null;
		return factory.createAttributeLiteral(key, value, null);
	}

	private static Properties getProperties(String filepath) {
		try (InputStream conf = new FileInputStream(filepath)) {
			Properties props = new Properties();
			props.load(conf);
			return props;
		} catch (FileNotFoundException e) {
			// Print the error stack trace.
			e.printStackTrace();
		} catch (IOException e) {
			// Print the error stack trace.
			e.printStackTrace();
		}
		return null;
	}
}
