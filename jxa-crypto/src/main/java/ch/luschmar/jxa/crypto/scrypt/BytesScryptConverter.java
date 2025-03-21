package ch.luschmar.jxa.crypto.scrypt;

public class BytesScryptConverter<I extends ScryptInput> extends ScryptConverter<I, byte[]> {
    @Override
    byte[] constructOutput(byte[] b) {
        return b;
    }
}
