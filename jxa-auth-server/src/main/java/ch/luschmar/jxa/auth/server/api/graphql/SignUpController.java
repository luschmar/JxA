package ch.luschmar.jxa.auth.server.api.graphql;

import ch.luschmar.jxa.auth.server.api.account.login.LoginResponse;
import ch.luschmar.jxa.auth.server.api.account.login.VerificationMethod;
import ch.luschmar.jxa.auth.server.api.graphql.input.SignUpInput;
import ch.luschmar.jxa.auth.server.service.AccountService;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.stereotype.Controller;

@Controller
public class SignUpController {
    private final AccountService accountService;

    public SignUpController(AccountService accountService) {
        this.accountService = accountService;
    }

    @MutationMapping
    public LoginResponse signUp(@Argument SignUpInput input) {
        var result = accountService.register(input.email(), input.authPW());

        return new LoginResponse(result.uid(), result.sessionToken(), result.keyFetchToken(), "", 0L, VerificationMethod.EMAIL);
    }
}
