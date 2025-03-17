package ch.luschmar.jxa.auth.server.password;

import java.security.SecureRandom;

public final class RandomComponent {
    private final SecureRandom random = new SecureRandom();

    public byte[] nextAuthSalt() {
        var authSalt = new byte[64];
        random.nextBytes(authSalt);
        return authSalt;
    }


    public String next_kA() {
        var authSalt = new byte[32];
        random.nextBytes(authSalt);
        return new String(authSalt);
    }

    public String next_wrapWrap_kB() {
        var authSalt = new byte[32];
        random.nextBytes(authSalt);
        return new String(authSalt);
    }
}
