package ch.luschmar.jxa.auth.server.password;

import org.springframework.security.crypto.codec.Hex;

import java.security.SecureRandom;

public final class RandomComponent {
    private final SecureRandom random = new SecureRandom();

    public byte[] nextAuthSalt() {
        var authSalt = new byte[64];
        random.nextBytes(authSalt);
        return authSalt;
    }


    public char[] next_kAHex() {
        var authSalt = new byte[32];
        random.nextBytes(authSalt);
        return Hex.encode(authSalt);
    }

    public char[] next_wrapWrap_kBHex() {
        var authSalt = new byte[32];
        random.nextBytes(authSalt);
        return Hex.encode(authSalt);
    }
}
