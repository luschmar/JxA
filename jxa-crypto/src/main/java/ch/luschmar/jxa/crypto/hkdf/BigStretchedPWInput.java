package ch.luschmar.jxa.crypto.hkdf;

import org.springframework.security.crypto.codec.Hex;

import java.util.Arrays;

public record BigStretchedPWInput(byte[] ikm) implements HKDFInput {
    public BigStretchedPWInput(String hexIkm) {
        this(Hex.decode(hexIkm));
    }

    @Override
    public byte[] salt() {
        return Arrays.copyOf("".getBytes(), 0);
    }

    @Override
    public byte[] info() {
        return "identity.mozilla.com/picl/v1/wrapwrapKey".getBytes();
    }

    @Override
    public int lenght() {
        return 3 * 32;
    }
}
