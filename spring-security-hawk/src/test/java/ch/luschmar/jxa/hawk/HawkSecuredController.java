package ch.luschmar.jxa.hawk;

import org.springframework.web.bind.annotation.*;

@RestController
public class HawkSecuredController {
    @GetMapping("/resource/{resId}")
    public @ResponseBody String resource(@PathVariable int resId) {
        return "Hello, World";
    }

    @PostMapping(value = "/resource/{resId}")
    public @ResponseBody String post(@PathVariable int resId, @RequestBody String body) {
        return "Hello, World";
    }
}
