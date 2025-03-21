package ch.luschmar.jxa.crypto.hkdf;

import java.util.Arrays;

public record KeyRequestKeyInput(byte[] ikm) implements HKDFInput {
    @Override
    public byte[] salt() {
        return Arrays.copyOf("".getBytes(), 0);
    }

    @Override
    public byte[] info() {
        return "identity.mozilla.com/picl/v1/account/keys".getBytes();
    }

    @Override
    public int lenght() {
        return 3 * 32;
    }
}
