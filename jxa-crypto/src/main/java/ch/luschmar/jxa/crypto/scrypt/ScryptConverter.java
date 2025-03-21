package ch.luschmar.jxa.crypto.scrypt;

import org.bouncycastle.crypto.generators.SCrypt;

public abstract class ScryptConverter<I extends ScryptInput, O> {
    public O calculate(I scryptInput) {
        return constructOutput(SCrypt.generate(scryptInput.passphrase(), scryptInput.salt(), 64 * 1024, 8, 1, 32));
    }

    abstract O constructOutput(byte[] b);
}