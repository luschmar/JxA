package ch.luschmar.jxa.crypto.hkdf;

import static java.util.Arrays.copyOfRange;

public class KeyFetchTokenFactory implements HKDFResultFactory<KeyFetchTokenResult> {
    public KeyFetchTokenResult create(byte[] result) {
        return new KeyFetchTokenResult(copyOfRange(result, 0, 32),
                copyOfRange(result, 32, 64),
                copyOfRange(result, 64, 96));
    }
}
