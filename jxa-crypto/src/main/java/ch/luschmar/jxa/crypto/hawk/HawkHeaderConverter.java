package ch.luschmar.jxa.crypto.hawk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.function.BiFunction;

public class HawkHeaderConverter implements BiFunction<HawkHeader, byte[], String> {
    @Override
    public String apply(HawkHeader hawkHeader, byte[] key) {
        var secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = null;
        try {
            mac = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            mac.init(secretKeySpec);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        var encodedHash = mac.doFinal(hawkHeader.toHawkBytes());
        return Base64.getEncoder().encodeToString(encodedHash);
    }
}
