package kz.kcsd.demo;

import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.utils.Constants;

public class KalkanUtils {

    private static final String GOST3410_256_2015 = "1.2.398.3.10.1.1.2.3.1";
    private static final String GOST3410_512_2015 = "1.2.398.3.10.1.1.2.3.2";

    private KalkanUtils() {
    }

    public static String[] getSignMethodByOID(String oid) {

        var ret = new String[2];

        if (oid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            ret[0] = org.apache.xml.security.utils.Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
            ret[1] = org.apache.xml.security.utils.Constants.MoreAlgorithmsSpecNS + "sha1";
        } else if (oid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            ret[0] = org.apache.xml.security.utils.Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
            ret[1] = XMLCipherParameters.SHA256;
        } else if (oid.equals(GOST3410_512_2015)) { // GOST3410-2015 512
            ret[0] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
            ret[1] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
        } else if (oid.equals(GOST3410_256_2015)) { // GOST3410-2015 256
            ret[0] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256";
            ret[1] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256";
        } else {
            ret[0] = org.apache.xml.security.utils.Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
            ret[1] = Constants.MoreAlgorithmsSpecNS + "gost34311";
        }
        return ret;
    }
}
