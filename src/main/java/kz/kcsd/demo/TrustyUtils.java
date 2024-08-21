package kz.kcsd.demo;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

import javax.security.auth.x500.X500PrivateCredential;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class TrustyUtils {

    private TrustyUtils() {
    }

    public static X500PrivateCredential loadCredentialFromFile(String path, String password) {
        try {
            var keyStore = KeyStore.getInstance("PKCS12", KalkanProvider.PROVIDER_NAME);

            try (InputStream in = new FileInputStream(path)) {
                return loadCredentialFromStream(password, keyStore, in);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static X500PrivateCredential loadCredentialFromStream(String password, KeyStore keyStore, InputStream in) {
        try {
            keyStore.load(in, password.toCharArray());
            var aliases = keyStore.aliases();
            if (aliases.hasMoreElements()) {
                var alias = aliases.nextElement();

                return new X500PrivateCredential(
                        (X509Certificate) keyStore.getCertificate(alias),
                        (PrivateKey) keyStore.getKey(alias, password.toCharArray()),
                        alias
                );
            }

            return null;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
