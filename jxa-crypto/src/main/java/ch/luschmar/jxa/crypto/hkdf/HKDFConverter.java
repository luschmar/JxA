package ch.luschmar.jxa.crypto.hkdf;


public abstract class HKDFConverter<I extends HKDFInput, O> {
    O calculate(I hkdfInput) {
        var prkVerifyHash = HKDF.hkdfExtract(hkdfInput.salt(), hkdfInput.ikm());
        return constructOutput(HKDF.hkdfExpand(prkVerifyHash, hkdfInput.info(), hkdfInput.lenght()));
    }

    abstract O constructOutput(byte[] b);
}