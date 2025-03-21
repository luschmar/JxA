package ch.luschmar.jxa.crypto.scrypt;

public interface ScryptInput {
    byte[] salt();

    byte[] passphrase();
}
