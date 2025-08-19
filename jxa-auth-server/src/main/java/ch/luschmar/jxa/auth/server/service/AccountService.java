package ch.luschmar.jxa.auth.server.service;

import ch.luschmar.jxa.auth.server.data.JxaUser;
import ch.luschmar.jxa.auth.server.data.JxaUserRepository;
import ch.luschmar.jxa.auth.server.password.OnepwPasswordEncoder;
import ch.luschmar.jxa.auth.server.password.RandomComponent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AccountService {
    private final JxaUserRepository jxaUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final RandomComponent randomComponent;

    public AccountService(JxaUserRepository jxaUserRepository, PasswordEncoder passwordEncoder, RandomComponent randomComponent) {
        this.jxaUserRepository = jxaUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.randomComponent = randomComponent;
    }

    public void register(String email, String authPw) {
        var encodedPwd = passwordEncoder.encode(authPw);
        var onePwd = new OnepwPasswordEncoder.OnePw(encodedPwd);

        jxaUserRepository.save(new JxaUser(null,
                email,
                onePwd.hexAuthSalt(),
                new String(randomComponent.next_kAHex()),
                new String(randomComponent.next_wrapWrap_kBHex()),
                onePwd.hexVerifyHash()));
    }
}
