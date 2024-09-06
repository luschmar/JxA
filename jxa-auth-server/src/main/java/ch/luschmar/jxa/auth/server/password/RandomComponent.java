package ch.luschmar.jxa.auth.server.password;

import java.util.Random;

public final class RandomComponent {
    private final Random random = new Random();

    public byte[] nextAuthSalt() {
        var authSalt = new byte[64];
        random.nextBytes(authSalt);
        return authSalt;
    }
}
