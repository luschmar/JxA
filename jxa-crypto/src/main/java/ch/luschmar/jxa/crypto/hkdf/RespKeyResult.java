package ch.luschmar.jxa.crypto.hkdf;

import org.springframework.security.crypto.codec.Hex;

public record RespKeyResult(byte[] respHMACkey, byte[] respXORKey) implements HKDFResult {

    String hexRespHMACkey() {
        return new String(Hex.encode(respHMACkey));
    }


    String hexRespXORKey() {
        return new String(Hex.encode(respXORKey));
    }

}