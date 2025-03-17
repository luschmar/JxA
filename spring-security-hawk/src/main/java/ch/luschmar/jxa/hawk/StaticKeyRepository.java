package ch.luschmar.jxa.hawk;

import java.util.Map;

public class StaticKeyRepository implements HawkKeyRepository {
    private final Map<String, byte[]> keyMap;

    public StaticKeyRepository() {
        this.keyMap = Map.of("dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn".getBytes());
    }

    public byte[] findKeyById(String keyId) {
        return keyMap.get(keyId);
    }
}
