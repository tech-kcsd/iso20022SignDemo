package kz.kcsd.demo;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

public class XmlSignDocumentResolver extends ResourceResolverSpi {
    private final String expression = String.format("//*[local-name()='%s']", "Document");
    private final Document document;

    public XmlSignDocumentResolver(Document document) {
        this.document = document;
    }

    @Override
    public XMLSignatureInput engineResolveURI(ResourceResolverContext context) {
        if (null == context.uriToResolve && document != null) {
            NodeList documentNodes;
            try {
                var xpath = XPathFactory.newInstance().newXPath();
                xpath.setNamespaceContext(new DSNamespaceContext());
                documentNodes = (NodeList) xpath.evaluate(expression, document, XPathConstants.NODESET);
            } catch (Exception e) {
                throw new SecurityException("Error occurred in document resolver:", e);
            }
            var selectedElem = documentNodes.item(0);
            if (selectedElem == null) {
                return null;
            }
            var result = new XMLSignatureInput(selectedElem);
            result.setSecureValidation(context.secureValidation);
            result.setExcludeComments(true);
            result.setMIMEType("text/xml");
            result.setSourceURI(null);
            return result;
        }
        return null;
    }

    @Override
    public boolean engineCanResolveURI(ResourceResolverContext context) {
        return null == context.uriToResolve && document != null;
    }

}
