package ch.luschmar.jxa.crypto.scrypt;

public record ScryptInputImpl(byte[] passphrase, byte[] salt) implements ScryptInput {
}
