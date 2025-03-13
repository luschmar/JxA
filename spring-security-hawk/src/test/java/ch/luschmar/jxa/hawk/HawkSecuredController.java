package ch.luschmar.jxa.hawk;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController("/hawk")
public class HawkSecuredController {

    @GetMapping("/test")
    public @ResponseBody String greeting() {
        return "something";
    }
}
