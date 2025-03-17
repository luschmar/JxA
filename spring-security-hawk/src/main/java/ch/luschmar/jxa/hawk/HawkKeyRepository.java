package ch.luschmar.jxa.hawk;

public interface HawkKeyRepository {
    byte[] findKeyById(String keyId);
}
