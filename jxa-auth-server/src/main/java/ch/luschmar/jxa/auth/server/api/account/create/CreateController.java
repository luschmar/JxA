package ch.luschmar.jxa.auth.server.api.account.create;

import ch.luschmar.jxa.auth.server.data.JxaUserRepository;
import ch.luschmar.jxa.auth.server.service.AccountService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/account")
public class CreateController {
    private final JxaUserRepository jxaUserRepository;
    private final AccountService accountService;

    public CreateController(JxaUserRepository jxaUserRepository, AccountService accountService) {
        this.jxaUserRepository = jxaUserRepository;
        this.accountService = accountService;
    }

    @PostMapping("/create")
    public String create(@Valid @RequestBody CreateRequest request) {
        var optUser = jxaUserRepository.findByEmail(request.email());
        if (optUser.isPresent()) {
            // TODO: prevent user enumeration
            throw new IllegalArgumentException("User already exists");
        }

        // TODO: Service registerUser
        accountService.register(request.email(), request.authPW());

        return "create/success";
    }
}
