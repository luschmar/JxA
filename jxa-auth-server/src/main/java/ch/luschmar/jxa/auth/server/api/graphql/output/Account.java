package ch.luschmar.jxa.auth.server.api.graphql.output;

import java.util.List;

public record Account(String uid, RecoveryKey recoveryKey, boolean metricsEnabled, List<Email> emails, Totp totp) {
}
