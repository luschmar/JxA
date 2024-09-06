package ch.luschmar.jxa.auth.server.password;

import ch.luschmar.jxa.crypto.BytesHKDFConverter;
import ch.luschmar.jxa.crypto.VerifyHashInput;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.bouncycastle.crypto.generators.SCrypt.generate;

public class OnepwPasswordEncoder implements PasswordEncoder {
    private final BytesHKDFConverter<VerifyHashInput> bytesHKDFConverter = new BytesHKDFConverter<>();
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
        var bigStretchedPW = generate(Hex.decode(strHexAuthPw), authSalt, 64 * 1024, 8, 1, 32);
        var verifyHash = bytesHKDFConverter.apply(new VerifyHashInput(bigStretchedPW));
        return new OnePw(Hex.toHexString(authSalt), Hex.toHexString(verifyHash)).toString();
    }

    @Override
    public boolean matches(CharSequence hexAuthPw, String encodedPassword) {
        var password = new OnePw(encodedPassword);
        var bigStretchedPW = generate(Hex.decode(hexAuthPw.toString()), Hex.decode(password.hexAuthSalt), 64 * 1024, 8, 1, 32);
        var verifyHash = Hex.toHexString(bytesHKDFConverter.apply(new VerifyHashInput(bigStretchedPW)));
        return verifyHash.equals(password.hexVerifyHash);
    }

    public record OnePw(String hexAuthSalt, String hexVerifyHash) {
        public OnePw(String hexAuthSaltAndVerifyHash) {
            this(hexAuthSaltAndVerifyHash.replace("{onepw}", "").split(":", 2)[0], hexAuthSaltAndVerifyHash.split(":", 2)[1]);
        }

        @Override
        public String toString() {
            return String.format("%s:%s", hexAuthSalt, hexVerifyHash);
        }
    }
}
