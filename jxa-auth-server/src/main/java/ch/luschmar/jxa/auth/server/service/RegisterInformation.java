package ch.luschmar.jxa.auth.server.service;

import java.util.UUID;

public record RegisterInformation(UUID uid, String sessionToken, long authAt, String keyFetchToken) {
}
