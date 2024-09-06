package ch.luschmar.jxa.crypto;

public interface HKDFResultFactory<R> {
    R create(byte[] result);
}
