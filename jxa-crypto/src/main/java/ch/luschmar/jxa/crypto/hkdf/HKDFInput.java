package ch.luschmar.jxa.crypto.hkdf;

public interface HKDFInput {
    byte[] salt();

    byte[] ikm();

    byte[] info();

    int lenght();
}
