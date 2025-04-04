import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class NrfSecurity {

    private RSAPrivateKey rootPrivateKey;
    private Certificate rootCertificate;
    private RSAPrivateKey nrfPrivateKey;
    private RSAPublicKey nrfPublicKey;
    private Certificate nrfCertificate;

    public void initSecurityKeys(String rootPrivKeyPath, String rootCertPath, String nrfPrivKeyPath, String nrfCertPath) throws Exception {
        rootPrivateKey = loadPrivateKey(rootPrivKeyPath);
        rootCertificate = loadCertificate(rootCertPath);

        nrfPrivateKey = loadPrivateKey(nrfPrivKeyPath);
        nrfPublicKey = (RSAPublicKey) nrfPrivateKey.getPublic();
        nrfCertificate = loadCertificate(nrfCertPath);
    }

    private RSAPrivateKey loadPrivateKey(String keyPath) throws Exception {
        if (!new File(keyPath).exists()) {
            System.out.println("No private key found, generating new one...");
            return generateRSAKeyPair(keyPath).getPrivate();
        }
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyPath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }

    private Certificate loadCertificate(String certPath) throws CertificateException, IOException {
        if (!new File(certPath).exists()) {
            System.out.println("No certificate found at " + certPath);
            return null;
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificate(Files.newInputStream(Paths.get(certPath)));
    }

    private KeyPair generateRSAKeyPair(String keyPath) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Files.write(Paths.get(keyPath), keyPair.getPrivate().getEncoded());
        return keyPair;
    }

    public boolean verifyOAuth(String token, String serviceName, String certPath) {
        // OAuth verification logic goes here (e.g., JWT verification using public key)
        System.out.println("Verifying OAuth token: " + token + " for service: " + serviceName);
        return true;
    }
}
