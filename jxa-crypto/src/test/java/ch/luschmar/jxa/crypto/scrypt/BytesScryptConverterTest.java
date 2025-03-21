package ch.luschmar.jxa.crypto.scrypt;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BytesScryptConverterTest {

    @Test
    void test() {
        var conv = new BytesScryptConverter<ScryptInputImpl>();

        var res = conv.calculate(new ScryptInputImpl(Hex.decode("247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375".getBytes()),
                Hex.decode("00f0000000000000000000000000000000000000000000000000000000000000".getBytes())));

        assertEquals("441509e25c92ee103d5a1a874e6f155df25a44d06e61c894616c9e85181dba97", new String(Hex.encode(res)));

    }
}