package ch.luschmar.jxa.auth.server.password;

import ch.luschmar.jxa.crypto.hkdf.BytesHKDFConverter;
import ch.luschmar.jxa.crypto.hkdf.VerifyHashInput;
import ch.luschmar.jxa.crypto.scrypt.BytesScryptConverter;
import ch.luschmar.jxa.crypto.scrypt.ScryptInputImpl;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.security.crypto.password.PasswordEncoder;

public class OnepwPasswordEncoder implements PasswordEncoder {
    public static final String ONEPW_ID = "onepw";

    private final BytesHKDFConverter<VerifyHashInput> bytesHKDFConverter = new BytesHKDFConverter<>();
    private final BytesScryptConverter<ScryptInputImpl> bigStretchedPWConverter = new BytesScryptConverter<>();
    private final RandomComponent randomComponent;

    public OnepwPasswordEncoder(RandomComponent randomComponent) {
        this.randomComponent = randomComponent;
    }

    @Override
    public String encode(CharSequence hexAuthPw) {
        var strHexAuthPw = hexAuthPw.toString();
        if (!strHexAuthPw.matches("[0-9a-f]+")) {
            strHexAuthPw = new String(Hex.encode(strHexAuthPw.getBytes()));
        }

        var authSalt = randomComponent.nextAuthSalt();

        var bigStretchedPW = bigStretchedPWConverter.calculate(new ScryptInputImpl(Hex.decode(strHexAuthPw), authSalt));
        var verifyHash = bytesHKDFConverter.apply(new VerifyHashInput(bigStretchedPW));
        return new OnePw(Hex.toHexString(authSalt), Hex.toHexString(verifyHash)).toString();
    }

    @Override
    public boolean matches(CharSequence hexAuthPw, String encodedPassword) {
        var password = new OnePw(encodedPassword);

        var bigStretchedPW = bigStretchedPWConverter.calculate(new ScryptInputImpl(Hex.decode(hexAuthPw.toString()), Hex.decode(password.hexAuthSalt)));
        var verifyHash = Hex.toHexString(bytesHKDFConverter.apply(new VerifyHashInput(bigStretchedPW)));
        return verifyHash.equals(password.hexVerifyHash);
    }

    public record OnePw(String hexAuthSalt, String hexVerifyHash) {
        public OnePw(String hexAuthSaltAndVerifyHash) {
            this(hexAuthSaltAndVerifyHash.replace("{%s}".formatted(ONEPW_ID), "").split(":", 2)[0], hexAuthSaltAndVerifyHash.split(":", 2)[1]);
        }

        @Override
        public String toString() {
            return String.format("%s:%s", hexAuthSalt, hexVerifyHash);
        }
    }
}
