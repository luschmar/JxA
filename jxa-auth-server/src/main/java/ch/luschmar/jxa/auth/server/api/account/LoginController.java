package ch.luschmar.jxa.auth.server.api.account;

import ch.luschmar.jxa.auth.server.data.JxaUserRepository;
import ch.luschmar.jxa.auth.server.password.OnepwPasswordEncoder;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/account")
public class LoginController {
    private final AuthenticationManager authenticationManager;
    private final JxaUserRepository jxaUserRepository;


    public LoginController(JxaUserRepository jxaUserRepository, AuthenticationManager authenticationManager) {
        this.jxaUserRepository = jxaUserRepository;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public String login(@Valid @RequestBody LoginRequest request) {
        var user = jxaUserRepository.findByEmail(request.email()).orElseThrow(() -> new UsernameNotFoundException(""));
        var onePw = new OnepwPasswordEncoder.OnePw(user.getAuthSalt(), request.authPW());

        var authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(request.email(),
                onePw.hexVerifyHash());
        // TODO:
        var authenticationResponse = authenticationManager.authenticate(authenticationRequest);
        return "success";
    }
}
