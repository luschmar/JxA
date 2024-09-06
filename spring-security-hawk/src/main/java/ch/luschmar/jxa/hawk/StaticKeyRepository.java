package ch.luschmar.jxa.hawk;

import java.util.Map;

public class StaticKeyRepository implements HawkKeyRepository {
    private final Map<String, String> keyMap;

    public StaticKeyRepository() {
        this.keyMap = Map.of("dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn");
    }

    public String findKeyById(String keyId) {
        return keyMap.get(keyId);
    }
}
