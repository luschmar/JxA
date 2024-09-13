package ch.luschmar.jxa.auth.server.api.account.status;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

/**
 * @see <a href="https://mozilla.github.io/ecosystem-platform/api#tag/Account/operation/postAccountStatus">Account Status</a>
 */
@RestController
@RequestMapping("/v1/account")
public class StatusController {

    @GetMapping("/status/{uid}")
    public StatusResponse status(@PathVariable String uid) {
        // return new StatusResponse(false, false, false, false);
        throw new UnsupportedOperationException();
    }

    @PostMapping("/status")
    public StatusResponse status(@RequestBody @Valid StatusRequest request) {
        //return new StatusResponse(false, false, false, false);
        throw new UnsupportedOperationException();
    }


}
