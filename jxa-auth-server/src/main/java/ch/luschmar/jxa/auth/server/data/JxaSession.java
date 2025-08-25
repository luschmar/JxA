package ch.luschmar.jxa.auth.server.data;

import jakarta.persistence.*;

import java.util.UUID;

@Entity
@Table(name = "jxa_session")
public class JxaSession {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    UUID sid;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "uid", referencedColumnName = "uid")
    private JxaUser user;

    public JxaSession(UUID sid, JxaUser user) {
        this.sid = sid;
        this.user = user;
    }

    public JxaUser getUser() {
        return user;
    }

    public void setUser(JxaUser user) {
        this.user = user;
    }

    public UUID getSid() {
        return sid;
    }

    public void setSid(UUID sid) {
        this.sid = sid;
    }
}
