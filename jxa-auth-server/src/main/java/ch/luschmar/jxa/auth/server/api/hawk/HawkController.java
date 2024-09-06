package ch.luschmar.jxa.auth.server.api.hawk;

import ch.luschmar.jxa.auth.server.api.account.CreateRequest;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/hawk")
public class HawkController {
    @GetMapping("/test")
    public String get(Authentication authentication) {
        return authentication.toString();
    }

    @PostMapping("/create")
    public void create(CreateRequest request) {
    }
}
