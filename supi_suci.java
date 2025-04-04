import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.parsers.ECIESPublicKeyParser;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;

public class SuciToSupiConverter {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Constants for Profile A
    private static final int PROFILE_A_MAC_KEY_LEN = 32; // octets
    private static final int PROFILE_A_ENC_KEY_LEN = 16; // octets
    private static final int PROFILE_A_ICB_LEN = 16;    // octets
    private static final int PROFILE_A_MAC_LEN = 8;     // octets
    private static final int PROFILE_A_HASH_LEN = 32;   // octets

    // Constants for Profile B
    private static final int PROFILE_B_MAC_KEY_LEN = 32; // octets
    private static final int PROFILE_B_ENC_KEY_LEN = 16; // octets
    private static final int PROFILE_B_ICB_LEN = 16;    // octets
    private static final int PROFILE_B_MAC_LEN = 8;     // octets
    private static final int PROFILE_B_HASH_LEN = 32;   // octets

    // SUPI Types
    private static final String TYPE_IMSI = "0";
    private static final String IMSI_PREFIX = "imsi-";
    private static final String NULL_SCHEME = "0";
    private static final String PROFILE_A_SCHEME = "1";
    private static final String PROFILE_B_SCHEME = "2";

    public static String toSupi(String suci, SuciProfile[] suciProfiles) throws Exception {
        String[] suciParts = suci.split("-");
        if (suciParts.length < 6) {
            throw new IllegalArgumentException("SUCI has an incorrect format.");
        }

        String suciPrefix = suciParts[0];
        if ("imsi".equals(suciPrefix) || "nai".equals(suciPrefix)) {
            return suci;
        } else if (!"suci".equals(suciPrefix)) {
            throw new IllegalArgumentException("Unknown SUCI prefix: " + suciPrefix);
        }

        String scheme = suciParts[5];
        String mccMnc = suciParts[2] + suciParts[3];
        String supiPrefix = IMSI_PREFIX;
        if (TYPE_IMSI.equals(suciParts[1])) {
            supiPrefix = IMSI_PREFIX;
        }

        if (NULL_SCHEME.equals(scheme)) {
            return supiPrefix + mccMnc + suciParts[suciParts.length - 1];
        }

        int keyIndex = Integer.parseInt(suciParts[6]);
        if (keyIndex > suciProfiles.length) {
            throw new IllegalArgumentException("Key index out of range.");
        }

        SuciProfile profile = suciProfiles[keyIndex - 1];
        if (!scheme.equals(profile.getProtectionScheme())) {
            throw new IllegalArgumentException("Protection scheme mismatch.");
        }

        String schemeOutput = suciParts[suciParts.length - 1];
        String supiType = suciParts[1];
        String privateKey = profile.getPrivateKey();

        if (PROFILE_A_SCHEME.equals(scheme)) {
            return supiPrefix + mccMnc + profileA(schemeOutput, supiType, privateKey);
        } else if (PROFILE_B_SCHEME.equals(scheme)) {
            return supiPrefix + mccMnc + profileB(schemeOutput, supiType, privateKey);
        } else {
            throw new IllegalArgumentException("Protection scheme not supported: " + scheme);
        }
    }

    private static String profileA(String input, String supiType, String privateKeyHex) throws Exception {
        byte[] s = hexStringToByteArray(input);

        int profileAPubKeyLen = 32;
        if (s.length < profileAPubKeyLen + PROFILE_A_MAC_LEN) {
            throw new IllegalArgumentException("Input data is too short.");
        }

        byte[] decryptMac = Arrays.copyOfRange(s, s.length - PROFILE_A_MAC_LEN, s.length);
        byte[] decryptPublicKey = Arrays.copyOfRange(s, 0, profileAPubKeyLen);
        byte[] decryptCipherText = Arrays.copyOfRange(s, profileAPubKeyLen, s.length - PROFILE_A_MAC_LEN);

        byte[] aHNPriv = hexStringToByteArray(privateKeyHex);
        byte[] decryptSharedKey = computeSharedSecretX25519(aHNPriv, decryptPublicKey);

        byte[] kdfKey = ansiX963KDF(decryptSharedKey, decryptPublicKey, PROFILE_A_ENC_KEY_LEN, PROFILE_A_MAC_KEY_LEN, PROFILE_A_HASH_LEN);
        byte[] decryptEncKey = Arrays.copyOfRange(kdfKey, 0, PROFILE_A_ENC_KEY_LEN);
        byte[] decryptIcb = Arrays.copyOfRange(kdfKey, PROFILE_A_ENC_KEY_LEN, PROFILE_A_ENC_KEY_LEN + PROFILE_A_ICB_LEN);
        byte[] decryptMacKey = Arrays.copyOfRange(kdfKey, kdfKey.length - PROFILE_A_MAC_KEY_LEN, kdfKey.length);

        byte[] decryptMacTag = hmacSha256(decryptCipherText, decryptMacKey, PROFILE_A_MAC_LEN);
        if (!Arrays.equals(decryptMacTag, decryptMac)) {
            throw new SecurityException("Decryption MAC failed.");
        }

        byte[] decryptPlainText = aes128Ctr(decryptCipherText, decryptEncKey, decryptIcb);
        return calcSchemeResult(decryptPlainText, supiType);
    }

    private static String profileB(String input, String supiType, String privateKeyHex) throws Exception {
        byte[] s = hexStringToByteArray(input);

        int profileB
::contentReference[oaicite:3]{index=3}
 
