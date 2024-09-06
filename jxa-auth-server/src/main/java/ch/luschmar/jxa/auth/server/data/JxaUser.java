package ch.luschmar.jxa.auth.server.data;

import jakarta.persistence.*;

import java.util.UUID;

@Entity
@Table(name = "jxa_user")
public class JxaUser {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    UUID uid;
    String email;
    String authSalt;
    String ka;
    String wrapwrapKb;
    String verifyHash;

    public JxaUser() {
    }

    public JxaUser(UUID uid, String email, String authSalt, String ka, String wrapwrapKb, String verifyHash) {
        this.uid = uid;
        this.email = email;
        this.authSalt = authSalt;
        this.ka = ka;
        this.wrapwrapKb = wrapwrapKb;
        this.verifyHash = verifyHash;
    }

    public UUID getUid() {
        return uid;
    }

    public void setUid(UUID uid) {
        this.uid = uid;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getAuthSalt() {
        return authSalt;
    }

    public void setAuthSalt(String authSalt) {
        this.authSalt = authSalt;
    }

    public String getKa() {
        return ka;
    }

    public void setKa(String ka) {
        this.ka = ka;
    }

    public String getWrapwrapKb() {
        return wrapwrapKb;
    }

    public void setWrapwrapKb(String wrapwrapKb) {
        this.wrapwrapKb = wrapwrapKb;
    }

    public String getVerifyHash() {
        return verifyHash;
    }

    public void setVerifyHash(String verifyHash) {
        this.verifyHash = verifyHash;
    }
}
