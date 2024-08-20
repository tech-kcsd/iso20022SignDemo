package kz.kcsd.demo;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;

import static kz.kcsd.demo.Constants.BAH_NAME_V01;

public class XmlSignBAHResolver extends ResourceResolverSpi {
    @Override
    public XMLSignatureInput engineResolveURI(ResourceResolverContext context) {
        var doc = context.attr.getOwnerElement().getOwnerDocument();
        if (context.uriToResolve.isEmpty()) {
            var bahNodes = doc.getElementsByTagNameNS(BAH_NAME_V01.getNamespaceURI(), BAH_NAME_V01.getLocalPart());
            var selectedElem = bahNodes.item(0);
            if (selectedElem == null) {
                return null;
            }
            var result = new XMLSignatureInput(selectedElem);
            result.setSecureValidation(context.secureValidation);
            result.setExcludeComments(true);
            result.setMIMEType("text/xml");
            result.setSourceURI(context.uriToResolve);
            return result;
        }
        return null;
    }

    @Override
    public boolean engineCanResolveURI(ResourceResolverContext context) {
        return null != context.uriToResolve && context.uriToResolve.isEmpty();
    }
}
