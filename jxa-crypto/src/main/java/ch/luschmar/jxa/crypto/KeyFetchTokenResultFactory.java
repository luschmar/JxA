package ch.luschmar.jxa.crypto;

import java.util.Arrays;

public class KeyFetchTokenResultFactory implements HKDFResultFactory<KeyFetchTokenResult> {
    public KeyFetchTokenResult create(byte[] result) {
        return new KeyFetchTokenResult(Arrays.copyOfRange(result, 0, 32),
                Arrays.copyOfRange(result, 32, 64),
                Arrays.copyOfRange(result, 64, 96));
    }
}
