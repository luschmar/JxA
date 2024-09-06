package ch.luschmar.jxa.auth.server.api.account;

import ch.luschmar.jxa.auth.server.data.JxaUser;
import ch.luschmar.jxa.auth.server.data.JxaUserRepository;
import ch.luschmar.jxa.auth.server.password.OnepwPasswordEncoder;
import ch.luschmar.jxa.crypto.BytesHKDFConverter;
import ch.luschmar.jxa.crypto.VerifyHashInput;
import jakarta.validation.Valid;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Random;
import java.util.UUID;

@RestController
@RequestMapping("/v1/account")
public class CreateController {
    private final PasswordEncoder passwordEncoder;
    private final Random random = new Random();
    private final BytesHKDFConverter<VerifyHashInput> bytesHKDFConverter = new BytesHKDFConverter<>();
    private final JxaUserRepository jxaUserRepository;
	
    public CreateController(JxaUserRepository jxaUserRepository, PasswordEncoder passwordEncoder) {
        this.jxaUserRepository = jxaUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/create")
    public String create(@Valid @RequestBody CreateRequest request) {
        var optUser = jxaUserRepository.findByEmail(request.email());
        if (optUser.isPresent()) {
            throw new IllegalArgumentException("User already exists");
        }

        var encodedPwd = passwordEncoder.encode(request.authPW());
        var onePwd = new OnepwPasswordEncoder.OnePw(encodedPwd);

        jxaUserRepository.save(new JxaUser(UUID.randomUUID(),
                request.email(),
                onePwd.hexAuthSalt(),
                null,
                null,
                onePwd.hexVerifyHash()));

        return "create/success";
    }
}
