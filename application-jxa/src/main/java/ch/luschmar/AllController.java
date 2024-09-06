package ch.luschmar;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AllController {
    @GetMapping("/**")
    public String index(HttpServletRequest request) {
        System.out.println(request.getRequestURI());
        return "test";
    }
}
