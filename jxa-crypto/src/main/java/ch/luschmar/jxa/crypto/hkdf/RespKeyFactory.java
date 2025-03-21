package ch.luschmar.jxa.crypto.hkdf;

import java.util.Arrays;

public class RespKeyFactory implements HKDFResultFactory<RespKeyResult> {
    public RespKeyResult create(byte[] result) {
        return new RespKeyResult(Arrays.copyOfRange(result, 0, 32),
                Arrays.copyOfRange(result, 32, 96));
    }
}
