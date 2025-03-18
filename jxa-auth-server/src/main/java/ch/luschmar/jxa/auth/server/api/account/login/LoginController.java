package ch.luschmar.jxa.auth.server.api.account.login;

import ch.luschmar.jxa.auth.server.data.JxaSession;
import ch.luschmar.jxa.auth.server.data.JxaSessionRepository;
import ch.luschmar.jxa.auth.server.data.JxaUserRepository;
import ch.luschmar.jxa.auth.server.password.OnepwPasswordEncoder;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/v1/account")
public class LoginController {
    private final AuthenticationManager authenticationManager;
    private final JxaUserRepository jxaUserRepository;
    private final JxaSessionRepository jxaSessionRepository;

    public LoginController(JxaUserRepository jxaUserRepository, JxaSessionRepository jxaSessionRepository, AuthenticationManager authenticationManager) {
        this.jxaUserRepository = jxaUserRepository;
        this.jxaSessionRepository = jxaSessionRepository;
        this.authenticationManager = authenticationManager;
    }

    /**
     * @see <a href="https://mozilla.github.io/ecosystem-platform/api#tag/Account/operation/postAccountFinish_setup">/account/login </a>
     */
    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request,
                               @RequestParam Optional<Boolean> keys,
                               @RequestParam Optional<String> service,
                               @RequestParam Optional<VerificationMethod> verificationMethod) {
        var user = jxaUserRepository.findByEmail(request.email()).orElseThrow(() -> new UsernameNotFoundException(""));
        var onePw = new OnepwPasswordEncoder.OnePw(user.getAuthSalt(), request.authPW());

        var authenticationRequest = UsernamePasswordAuthenticationToken
                .unauthenticated(request.email(),
                        onePw.hexVerifyHash());
        var authenticationResponse = authenticationManager.authenticate(authenticationRequest);

        var newSession = jxaSessionRepository.save(new JxaSession(user));

        return new LoginResponse(user.getUid(), newSession.getSessionToken(), 0L);
    }
}
