package ch.luschmar.jxa.crypto;


import java.util.function.Function;

public class BytesHKDFConverter<T extends HKDFInput> implements Function<T, byte[]> {
    @Override
    public byte[] apply(T hkdfInput) {
        var prkVerifyHash = HKDF.hkdfExtract(hkdfInput.salt(), hkdfInput.ikm());
        return HKDF.hkdfExpand(prkVerifyHash, hkdfInput.info(), hkdfInput.lenght());
    }
}