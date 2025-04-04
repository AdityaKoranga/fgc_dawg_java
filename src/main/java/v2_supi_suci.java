import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.*;

public class SuciProcessor {
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final String AES_ALGO = "AES/CTR/NoPadding";

    public static byte[] hmacSha256(byte[] input, byte[] macKey, int macLen) throws Exception {
        Mac hmac = Mac.getInstance(HMAC_ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(macKey, HMAC_ALGO);
        hmac.init(keySpec);
        byte[] macVal = hmac.doFinal(input);
        return Arrays.copyOf(macVal, macLen);
    }

    public static byte[] aes128ctr(byte[] input, byte[] encKey, byte[] icb) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(encKey, "AES");
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(icb));
        return cipher.doFinal(input);
    }

    public static byte[] ansiX963KDF(byte[] sharedKey, byte[] publicKey, int encKeyLen, int macKeyLen, int hashLen) throws NoSuchAlgorithmException {
        int kdfRounds = (int) Math.ceil((double) (encKeyLen + macKeyLen) / hashLen);
        ByteBuffer buffer = ByteBuffer.allocate(kdfRounds * hashLen);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        for (int i = 1; i <= kdfRounds; i++) {
            digest.update(ByteBuffer.allocate(4).putInt(i).array());
            digest.update(sharedKey);
            digest.update(publicKey);
            buffer.put(digest.digest());
        }
        return Arrays.copyOf(buffer.array(), encKeyLen + macKeyLen);
    }

    public static KeyPair generateECDHKeyPair(String curveName) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] ecdhSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        return ka.generateSecret();
    }

    public static void main(String[] args) {
        try {
            KeyPair keyPair = generateECDHKeyPair("secp256r1");
            byte[] sharedSecret = ecdhSecret(keyPair.getPrivate(), keyPair.getPublic());
            System.out.println("Shared Secret: " + Base64.getEncoder().encodeToString(sharedSecret));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
