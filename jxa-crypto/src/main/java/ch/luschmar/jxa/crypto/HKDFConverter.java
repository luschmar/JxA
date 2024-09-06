package ch.luschmar.jxa.crypto;


public abstract class HKDFConverter<I extends HKDFInput, O> {
    O calculate(I hkdfInput) {
        var prkVerifyHash = HKDF.hkdfExtract(hkdfInput.salt(), hkdfInput.ikm());
        return constuctOutput(HKDF.hkdfExpand(prkVerifyHash, hkdfInput.info(), hkdfInput.lenght()));
    }
    abstract O constuctOutput(byte[] b);
}