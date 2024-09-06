package ch.luschmar.jxa.hawk;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class HawkAuthenticationToken extends UsernamePasswordAuthenticationToken {
    public HawkAuthenticationToken(HawkCredentials cred) {
        super(null, cred);
    }
}
