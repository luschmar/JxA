package ch.luschmar.jxa.auth.server.api.account.login;

import java.util.UUID;

public record LoginResponse(UUID uid, String sessionToken, String keyFetchToken, String keyFetchTokenVersion2,
                            long authAt, VerificationMethod verificationMethod) {
    LoginResponse(UUID uid, String sessionToken, long authAt) {
        this(uid, sessionToken, null, null, authAt, null);
    }
}
