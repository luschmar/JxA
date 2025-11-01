package ch.luschmar.jxa.auth.server.api.graphql.output;

public record Email(String email, boolean isPrimary, boolean verified) {
}