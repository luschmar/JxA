package ch.luschmar.jxa.auth.server.api.graphql;

import ch.luschmar.jxa.auth.server.api.account.login.LoginResponse;
import ch.luschmar.jxa.auth.server.api.account.login.VerificationMethod;
import ch.luschmar.jxa.auth.server.api.graphql.input.SignUpInput;
import ch.luschmar.jxa.auth.server.api.graphql.output.Account;
import ch.luschmar.jxa.auth.server.api.graphql.output.Email;
import ch.luschmar.jxa.auth.server.service.AccountService;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;

import java.util.List;
import java.util.Objects;

@Controller
public class AccountController {
    private final AccountHolder accountHolder;
    private final AccountService accountService;

    public AccountController(AccountService accountService, AccountHolder accountHolder) {
        this.accountService = accountService;
        this.accountHolder = accountHolder;
    }

    @MutationMapping
    public LoginResponse signUp(@Argument SignUpInput input) {
        var result = accountService.register(input.email(), input.authPW());
        accountHolder.saveOrUpdateSession(result.sessionToken(), input.email());
        System.out.println(accountHolder.getId());
        return new LoginResponse(result.uid(), result.sessionToken(), result.keyFetchToken(), "", 0L, VerificationMethod.EMAIL);
    }

    @QueryMapping
    public Account account() {
        var sessionId = accountHolder.getSessionToken();
        var email = accountHolder.getEmail();
        System.out.println(accountHolder.getId());
        return new Account(sessionId, null, false, List.of(new Email(email, true, true)), null);
    }

    @QueryMapping
    public boolean isValidToken(@Argument String sessionToken) {
        System.out.println(accountHolder.getId());
        return Objects.equals(accountHolder.getSessionToken(), sessionToken);
    }
}
