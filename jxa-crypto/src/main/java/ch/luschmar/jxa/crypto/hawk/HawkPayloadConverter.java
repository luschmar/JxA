package ch.luschmar.jxa.crypto.hawk;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.function.Function;

public class HawkPayloadConverter implements Function<HawkPayload, String> {
    @Override
    public String apply(HawkPayload payload) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] hash = digest.digest(payload.toHawkBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
}
