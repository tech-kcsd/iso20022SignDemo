package kz.kcsd.demo;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.xmldsig.KncaXS;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.security.Security;
import java.util.Set;
import java.util.UUID;

import static kz.kcsd.demo.Constants.*;
import static kz.kcsd.demo.KalkanUtils.getSignMethodByOID;
import static kz.kcsd.demo.TrustyUtils.loadCredentialFromFile;
import static kz.kcsd.demo.XmlUtils.createXmlDocumentFromString;
import static kz.kcsd.demo.XmlUtils.getStringFromDocument;

public class Main {

    public static final String XML_SAMPLE = """
            <?xml version="1.0" encoding="UTF-8" ?>
            <Envelope>
            <h:AppHdr xmlns:h="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
            <h:Fr>
            <h:OrgId>
            <h:Id>
            <h:OrgId>
            <h:Othr>
            <h:Id>123456789012</h:Id>
            <h:SchmeNm>
            <h:Cd>COID</h:Cd>
            </h:SchmeNm>
            </h:Othr>
            </h:OrgId>
            </h:Id>
            </h:OrgId>
            </h:Fr>
            <h:To>
            <h:FIId>
            <h:FinInstnId>
            <h:BICFI>CEDUKZKA</h:BICFI>
            </h:FinInstnId>
            </h:FIId>
            </h:To>
            <h:BizMsgIdr>BC-CT-123123</h:BizMsgIdr>
            <h:MsgDefIdr>camt.060.001.06</h:MsgDefIdr>
            <h:CreDt>2024-08-19T11:53:00.688+05:00</h:CreDt>
            </h:AppHdr>
            <Doc:Document xmlns:Doc="urn:iso:std:iso:20022:tech:xsd:camt.060.001.06">
            <Doc:AcctRptgReq>
            <Doc:GrpHdr>
            <Doc:MsgId>BC-CT-123123</Doc:MsgId>
            <Doc:CreDtTm>2024-08-19T11:53:00.712+05:00</Doc:CreDtTm>
            </Doc:GrpHdr>
            <Doc:RptgReq>
            <Doc:ReqdMsgNmId>camt.053.001.10</Doc:ReqdMsgNmId>
            <Doc:Acct>
            <Doc:Id>
            <Doc:Othr>
            <Doc:Id>KZ123456789012345678</Doc:Id>
            </Doc:Othr>
            </Doc:Id>
            <Doc:Ccy>KZT</Doc:Ccy>
            </Doc:Acct>
            <Doc:AcctOwnr>
            <Doc:Pty>
            <Doc:Id>
            <Doc:OrgId>
            <Doc:Othr>
            <Doc:Id>123456789012</Doc:Id>
            <Doc:SchmeNm>
            <Doc:Cd>COID</Doc:Cd>
            </Doc:SchmeNm>
            </Doc:Othr>
            </Doc:OrgId>
            </Doc:Id>
            </Doc:Pty>
            </Doc:AcctOwnr>
            <Doc:RptgPrd>
            <Doc:FrToDt>
            <Doc:FrDt>2024-02-10</Doc:FrDt>
            <Doc:ToDt>2024-02-12</Doc:ToDt>
            </Doc:FrToDt>
            <Doc:Tp>ALLL</Doc:Tp>
            </Doc:RptgPrd>
            </Doc:RptgReq>
            </Doc:AcctRptgReq>
            </Doc:Document>
            </Envelope>
            """;

    static {
        if (Security.getProvider(KalkanProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new KalkanProvider());
            KncaXS.loadXMLSecurity();
            System.out.println("Initialized crypto provider with name " + Security.getProvider(KalkanProvider.PROVIDER_NAME));
        }
    }

    public static void main(String[] args) throws Exception {
        var certPath = findCertPath(args);
        var password = findPassword(args);

        System.out.println(
                new Main().sign(
                        XML_SAMPLE,
                        certPath,
                        password
                )
        );
    }

    private static String findCertPath(String[] args) {
        for (var i = 0; i < args.length; i += 2) {
            if (args[i].equals("--cert")) {
                return args[i + 1];
            }
        }
        throw new RuntimeException("Cert path not found!");
    }

    private static String findPassword(String[] args) {
        for (var i = 0; i < args.length; i += 2) {
            if (args[i].equals("--password")) {
                return args[i + 1];
            }
        }
        throw new RuntimeException("Password not found!");
    }

    public String sign(String xml, String certPath, String password) throws Exception {
        var document = createXmlDocumentFromString(xml);
        var keyStore = loadCredentialFromFile(certPath, password);
        var x509Certificate = keyStore.getCertificate();
        var privateKey = keyStore.getPrivateKey();

        var bahNodes = document.getElementsByTagNameNS(BAH_NAME_V01.getNamespaceURI(), BAH_NAME_V01.getLocalPart());
        var bahElement = (Element) bahNodes.item(0);
        var sgntrElement = document.createElementNS(WS_SECURITY_NAME_V01.getNamespaceURI(), WS_SECURITY_NAME_V01.getLocalPart());
        sgntrElement.setPrefix(bahElement.getPrefix());
        bahElement.appendChild(sgntrElement);

        var methods = getSignMethodByOID(x509Certificate.getSigAlgOID());

        var xmlSignature = new XMLSignature(document,
                BAH_NAME_V01.getNamespaceURI(),
                methods[0],
                CanonicalizationMethod.INCLUSIVE
        );
        sgntrElement.appendChild(xmlSignature.getElement());

        var keyInfo = xmlSignature.getKeyInfo();
        keyInfo.add(new X509Data(document));

        keyInfo.itemX509Data(0).addCertificate(x509Certificate);
        xmlSignature.addResourceResolver(new XmlSignBAHResolver());
        xmlSignature.addResourceResolver(new XmlSignDocumentResolver(document));

        var xpf = XPathFactory.newInstance();
        var xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());
        var expression = getExpression();
        var elementsToSign = (NodeList) xpath.evaluate(expression, document, XPathConstants.NODESET);
        for (int i = 0; i < elementsToSign.getLength(); i++) {
            var elementToSign = (Element) elementsToSign.item(i);
            var elementName = elementToSign.getLocalName();
            var id = UUID.randomUUID().toString();
            var transforms = new Transforms(document);
            if (
                    SECUREMENT_ACTION_TRANSFORMER_EXCLUSION.equals(elementName)
                    || SECUREMENT_ACTION_EXCLUSION.equals(elementName)
            ) {
                transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
                transforms.addTransform(XMLCipherParameters.N14C_XML_CMMNTS);
                xmlSignature.addDocument("", transforms, methods[1]);
            } else {
                transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
                elementToSign.setAttributeNS(null, "Id", id);
                elementToSign.setIdAttributeNS(null, "Id", true);
                xmlSignature.addDocument("#" + id, transforms, methods[1]);
            }
        }
        xmlSignature.sign(privateKey);
        return getStringFromDocument(document);
    }

    private String getExpression() {
        var securementActionBuffer = new StringBuilder();
        Set.of(
                SECUREMENT_ACTION_TRANSFORMER_EXCLUSION,
                "KeyInfo",
                SECUREMENT_ACTION_EXCLUSION
        ).forEach(securementAction -> {
            securementActionBuffer.append(String.format("//*[local-name()='%s']", securementAction));
            securementActionBuffer.append(String.format("%s", SECUREMENT_ACTION_SEPARATOR));
        });
        var returnValue = securementActionBuffer.toString();
        return returnValue.substring(0, returnValue.length() - SECUREMENT_ACTION_SEPARATOR.length());
    }
}
