package kz.kcsd.demo;

import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

public class XmlUtils {

    private XmlUtils() {
    }

    public static Document createXmlDocumentFromString(String xmlString) throws Exception {
        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setExpandEntityReferences(false);
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xmlString.getBytes(StandardCharsets.UTF_8)));
    }

    public static String getStringFromDocument(Document doc) throws TransformerException {
        var domSource = new DOMSource(doc);
        var writer = new StringWriter();
        var result = new StreamResult(writer);
        TransformerFactory.newInstance().newTransformer().transform(domSource, result);
        return writer.toString();
    }
}
