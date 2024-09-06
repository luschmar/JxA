package ch.luschmar.jxa.crypto;

import org.springframework.security.crypto.codec.Hex;

import java.util.Arrays;

public record KeyFetchTokenInput(byte[] ikm) implements HKDFInput {
    public KeyFetchTokenInput(String hexIkm) {
        this(Hex.decode(hexIkm));
    }
    @Override
    public byte[] salt() {
        return Arrays.copyOf("".getBytes(), 0);
    }

    @Override
    public byte[] info() {
        return "identity.mozilla.com/picl/v1/keyFetchToken".getBytes();
    }

    @Override
    public int lenght() {
        return 3*32;
    }
}
