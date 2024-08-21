package kz.kcsd.demo;

import javax.xml.namespace.QName;

public class Constants {

    public static final String SECUREMENT_ACTION_TRANSFORMER_EXCLUSION = "AppHdr";
    public static final String SECUREMENT_ACTION_EXCLUSION = "Document";
    public static final QName BAH_NAME_V01 = new QName("urn:iso:std:iso:20022:tech:xsd:head.001.001.01", SECUREMENT_ACTION_TRANSFORMER_EXCLUSION);
    public static final QName WS_SECURITY_NAME_V01 = new QName("urn:iso:std:iso:20022:tech:xsd:head.001.001.01", "Sgntr");
    public static final String SECUREMENT_ACTION_SEPARATOR = " | ";

    private Constants() {
    }
}
