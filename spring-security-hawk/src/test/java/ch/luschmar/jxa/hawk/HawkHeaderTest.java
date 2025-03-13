package ch.luschmar.jxa.hawk;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HawkHeaderTest {
    @Test
    void toHawkString() throws NoSuchAlgorithmException, InvalidKeyException {
        var timestamp = "1353832234";
        var nonce = "j4h3g2";
        var method = "GET";
        var path = "/resource/1?b=1&a=2";
        var host = "example.com";
        var port = 8000;
        var ext = "some-app-ext-data";

        var header = new HawkHeader(timestamp, nonce, method, path, host, port, ext);

        //Key identifier: dh37fgj492je
        //Key: werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn

        var secretKeySpec = new SecretKeySpec("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn".getBytes(), "HmacSHA256");
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        var intermediate = mac.doFinal(header.toHawkString().getBytes());
        var encodedHash = Base64.getEncoder().encodeToString(intermediate);
        assertEquals("6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=", encodedHash);
    }
}