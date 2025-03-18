package ch.luschmar.jxa.auth.server.data;

import jakarta.persistence.*;

import java.util.UUID;

@Entity
@Table(name = "jxa_session")
public class JxaSession {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    UUID sessionToken;
    @ManyToOne
    @JoinColumn(name = "uid", nullable = false)
    private JxaUser user;

    public JxaSession() {
    }

    public JxaSession(JxaUser user) {
        this.user = user;
    }

    public UUID getSessionToken() {
        return sessionToken;
    }

    public void setSessionToken(UUID sessionToken) {
        this.sessionToken = sessionToken;
    }

    public JxaUser getUser() {
        return user;
    }

    public void setUser(JxaUser user) {
        this.user = user;
    }
}
