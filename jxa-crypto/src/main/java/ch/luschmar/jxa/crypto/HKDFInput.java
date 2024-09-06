package ch.luschmar.jxa.crypto;

public interface HKDFInput {
    byte[] salt();
    byte[] ikm();
    byte[] info();
    int lenght();
}
