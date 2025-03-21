package ch.luschmar.jxa.crypto.hkdf;

import org.springframework.security.crypto.codec.Hex;

import java.util.stream.IntStream;

public record WrapKb(byte[] wrapKb) {
    public WrapKb(WrapWrapKeyResult wrapWrapKey, byte[] wrapWrapKb) {
        this(xor(wrapWrapKey.wrapWrapKey(), wrapWrapKb));
    }

    String hexWrapKb() {
        return new String(Hex.encode(wrapKb));
    }

    private static byte[] xor(byte[] wrapWrapKey, byte[] wrapWrapKb) {
        var xor = new byte[wrapWrapKey.length];
        IntStream.range(0, wrapWrapKey.length).forEach(idx -> xor[idx] = (byte) (wrapWrapKey[idx] ^ wrapWrapKb[idx]));
        return xor;
    }
}
