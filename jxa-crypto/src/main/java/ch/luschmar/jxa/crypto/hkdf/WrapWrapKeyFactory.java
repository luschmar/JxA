package ch.luschmar.jxa.crypto.hkdf;

import java.util.Arrays;

public class WrapWrapKeyFactory implements HKDFResultFactory<WrapWrapKeyResult> {
    public WrapWrapKeyResult create(byte[] result) {
        return new WrapWrapKeyResult(Arrays.copyOfRange(result, 0, 32));
    }
}
