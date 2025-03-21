package ch.luschmar.jxa.crypto.hkdf;

import org.springframework.security.crypto.codec.Hex;

public record WrapWrapKeyResult(byte[] wrapWrapKey) implements HKDFResult {
    String hexWrapWrapKey() {
        return new String(Hex.encode(wrapWrapKey));
    }
}
