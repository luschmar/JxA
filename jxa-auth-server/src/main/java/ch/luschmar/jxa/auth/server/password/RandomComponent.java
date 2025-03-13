package ch.luschmar.jxa.auth.server.password;

import java.security.SecureRandom;

public final class RandomComponent {
    private final SecureRandom random = new SecureRandom();

    public byte[] nextAuthSalt() {
        var authSalt = new byte[64];
        random.nextBytes(authSalt);
        return authSalt;
    }
}
