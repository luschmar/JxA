package ch.luschmar.jxa.auth.server.api.account.status;

public record StatusResponse(boolean exists,
                             boolean hasLinkedAccount,
                             boolean hasPassword,
                             boolean invalidDomain) {
}
