import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class EapAkaPrimeHandler {
    
    public static String encodeAttribute(String attributeType, String data) throws Exception {
        String attribute = "";
        int length;

        switch (attributeType) {
            case "AT_RAND":
            case "AT_AUTN":
                length = data.length() / 8 + 1;
                if (length != 5) {
                    throw new Exception("[EapEncodeAttribute] " + attributeType + " Length Error");
                }
                attribute = String.format("%02x05%s%s", getAttributeNumber(attributeType), "0000", data);
                break;

            case "AT_KDF":
                attribute = String.format("%02x010001", getAttributeNumber(attributeType));
                break;
            
            case "AT_MAC":
                attribute = String.format("%02x05%s%s", getAttributeNumber(attributeType), "0000", "00000000000000000000000000000000");
                break;
                
            default:
                throw new Exception("UNKNOWN attributeType " + attributeType);
        }
        return hexStringToBytes(attribute);
    }

    public static byte[] prf(String ikPrime, String ckPrime, String identity) throws Exception {
        byte[] key = hexStringToBytes(ikPrime + ckPrime);
        byte[] sBase = ("EAP-AKA'" + identity).getBytes(StandardCharsets.UTF_8);
        byte[] MK = new byte[208];
        byte[] prev = new byte[0];
        int prfRounds = 208 / 32 + 1;

        for (int i = 0; i < prfRounds; i++) {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] s = concat(prev, concat(sBase, new byte[]{(byte) (i + 1)}));
            prev = hmac.doFinal(s);
            System.arraycopy(prev, 0, MK, i * 32, prev.length);
        }

        return MK;
    }
    
    private static byte[] hexStringToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    private static byte[] concat(byte[]... arrays) {
        int totalLength = Arrays.stream(arrays).mapToInt(a -> a.length).sum();
        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        for (byte[] array : arrays) {
            buffer.put(array);
        }
        return buffer.array();
    }

    private static int getAttributeNumber(String attributeType) {
        Map<String, Integer> attributes = new HashMap<>();
        attributes.put("AT_RAND", 1);
        attributes.put("AT_AUTN", 2);
        attributes.put("AT_KDF", 3);
        attributes.put("AT_MAC", 4);
        return attributes.getOrDefault(attributeType, -1);
    }
}
