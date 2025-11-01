package ch.luschmar.jxa.auth.server.api.graphql;

import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

import java.io.Serializable;
import java.util.UUID;

@Component
@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class AccountHolder implements Serializable {
    private final String id;            // Unique bean ID
    private String sessionToken;
    private String email;

    public AccountHolder() {
        id = UUID.randomUUID().toString();
    }

    public String getId() {
        return id;
    }

    public void saveOrUpdateSession(String sessionToken, String email) {
        this.sessionToken = sessionToken;
        this.email = email;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setSessionToken(String sessionToken) {
        this.sessionToken = sessionToken;
    }
}
