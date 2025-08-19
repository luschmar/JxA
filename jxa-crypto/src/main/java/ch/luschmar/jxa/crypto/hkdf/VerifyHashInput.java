package ch.luschmar.jxa.crypto.hkdf;

import org.springframework.security.crypto.codec.Hex;

import static java.util.Arrays.copyOf;

public record VerifyHashInput(byte[] ikm) implements HKDFInput {
    public VerifyHashInput(String hexIkm) {
        this(Hex.decode(hexIkm));
    }

    @Override
    public byte[] salt() {
        return copyOf("".getBytes(), 0);
    }

    @Override
    public byte[] info() {
        return "identity.mozilla.com/picl/v1/verifyHash".getBytes();
    }

    @Override
    public int lenght() {
        return 32;
    }
}
