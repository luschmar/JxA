package ch.luschmar.jxa.auth.server;

import ch.luschmar.jxa.crypto.HKDF;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.codec.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.bouncycastle.crypto.generators.SCrypt.generate;
import static org.junit.jupiter.api.Assertions.assertEquals;


class AuthServiceTest {
    /**
     * https://mozilla.github.io/ecosystem-platform/explanation/onepw-protocol
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     */
    @Test
    void scratchpad() throws NoSuchAlgorithmException, InvalidKeySpecException {
        var hex = Hex.encode("andré@example.org".getBytes());
        var encoded = new String(hex);
        var hexString = "616e6472c3a9406578616d706c652e6f7267";

        assertEquals(hexString, encoded);

        var p = new String(Hex.decode("70c3a4737377c3b67264"));
        assertEquals("pässwörd", p);


        var skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        var chaaaa = "pässwörd".toCharArray();
        var spec = new PBEKeySpec(chaaaa, "identity.mozilla.com/picl/v1/quickStretch:andré@example.org".getBytes(), 1000, 256);
        var key = skf.generateSecret(spec);
        byte[] quickStretchedPW = key.getEncoded();

        assertEquals("e4e8889bd8bd61ad6de6b95c059d56e7b50dacdaf62bd84644af7e2add84345d", new String(Hex.encode(quickStretchedPW)));

        var prk = HKDF.hkdfExtract("".getBytes(), quickStretchedPW);
        var authPW = HKDF.hkdfExpand(prk, "identity.mozilla.com/picl/v1/authPW".getBytes(), 32);

        assertEquals("247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375", new String(Hex.encode(authPW)));


        var salt = Hex.decode("00f0000000000000000000000000000000000000000000000000000000000000");


        var bigStretchedPW = generate(authPW, salt, 64 * 1024, 8, 1, 32);

        assertEquals("441509e25c92ee103d5a1a874e6f155df25a44d06e61c894616c9e85181dba97", new String(Hex.encode(bigStretchedPW)));

        var prkVerifyHash = HKDF.hkdfExtract("".getBytes(), bigStretchedPW);
        var verifyHash = HKDF.hkdfExpand(prkVerifyHash, "identity.mozilla.com/picl/v1/verifyHash".getBytes(), 32);

        assertEquals("a4765bf103dc057f4cf4bc2c131ddb6716e8a4333cc55e1d3c449f31f0eec4f1", new String(Hex.encode(verifyHash)));


        /**
         email: 616e6472c3a9406578616d706c652e6f7267
         password: 70c3a4737377c3b6 7264
         quickStretchedPW: e4e8889bd8bd61ad6de6b95c059d56e7b50dacdaf62bd84644af7e2add84345d
         authPW: 247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375
         authSalt (normally random): 00f0000000000000000000000000000000000000000000000000000000000000
         bigStretchedPW: 441509e25c92ee103d5a1a874e6f155df25a44d06e61c894616c9e85181dba97
         verifyHash: a4765bf103dc057f4cf4bc2c131ddb6716e8a4333cc55e1d3c449f31f0eec4f1
         **/
    }
}