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
            <Envelope xmlns="urn:KACDBusinessEnvelope"
                xmlns:ns2="urn:iso:std:iso:20022:tech:xsd:semt.021.001.06"
                xmlns:ns4="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
                <ns4:AppHdr>
                    <ns4:Fr>
                        <ns4:OrgId>
                            <ns4:Nm>"Test"</ns4:Nm>
                            <ns4:Id>
                                <ns4:OrgId>
                                    <ns4:Othr>
                                        <ns4:Id>123456789012</ns4:Id>
                                    </ns4:Othr>
                                </ns4:OrgId>
                            </ns4:Id>
                        </ns4:OrgId>
                    </ns4:Fr>
                    <ns4:To>
                        <ns4:OrgId>
                            <ns4:Nm>АО "Центральный депозитарий ценных бумаг" Республика Казахстан</ns4:Nm>
                            <ns4:Id>
                                <ns4:OrgId>
                                    <ns4:AnyBIC>CEDUKZKA</ns4:AnyBIC>
                                    <ns4:Othr>
                                        <ns4:Id>970740000154</ns4:Id>
                                    </ns4:Othr>
                                </ns4:OrgId>
                            </ns4:Id>
                        </ns4:OrgId>
                    </ns4:To>
                    <ns4:BizMsgIdr>2023-03-16//none</ns4:BizMsgIdr>
                    <ns4:MsgDefIdr>semt.021.001.06</ns4:MsgDefIdr>
                    <ns4:CreDt>2023-03-16T09:55:00Z</ns4:CreDt>
                </ns4:AppHdr>
                <ns2:Document>
                    <ns2:SctiesStmtQry>
                        <ns2:StmtReqd>
                            <ns2:Nb>
                                <ns2:LngNb>semt.017.001.08</ns2:LngNb>
                            </ns2:Nb>
                        </ns2:StmtReqd>
                        <ns2:StmtGnlDtls>
                            <ns2:StmtDtOrPrd>
                                <ns2:StmtPrd>
                                    <ns2:FrDtToDt>
                                        <ns2:FrDt>2023-01-01</ns2:FrDt>
                                        <ns2:ToDt>2023-01-10</ns2:ToDt>
                                    </ns2:FrDtToDt>
                                </ns2:StmtPrd>
                            </ns2:StmtDtOrPrd>
                            <ns2:Frqcy>
                                <ns2:Cd>ADHO</ns2:Cd>
                            </ns2:Frqcy>
                            <ns2:UpdTp>
                                <ns2:Cd>COMP</ns2:Cd>
                            </ns2:UpdTp>
                            <ns2:StmtBsis>
                                <ns2:Cd>SETT</ns2:Cd>
                            </ns2:StmtBsis>
                        </ns2:StmtGnlDtls>
                        <ns2:AcctOwnr>
                            <ns2:Id>
                                <ns2:PrtryId>
                                    <ns2:Issr>INCL</ns2:Issr>
                                </ns2:PrtryId>
                            </ns2:Id>
                        </ns2:AcctOwnr>
                        <ns2:SfkpgAcct>
                            <ns2:Id>10308</ns2:Id>
                        </ns2:SfkpgAcct>
                    </ns2:SctiesStmtQry>
                </ns2:Document>
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
