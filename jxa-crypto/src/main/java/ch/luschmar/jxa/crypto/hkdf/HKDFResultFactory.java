package ch.luschmar.jxa.crypto.hkdf;

public interface HKDFResultFactory<R> {
    R create(byte[] result);
}
