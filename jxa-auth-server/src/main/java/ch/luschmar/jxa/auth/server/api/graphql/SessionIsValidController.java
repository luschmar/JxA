package ch.luschmar.jxa.auth.server.api.graphql;

import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;

@Controller
public class SessionIsValidController {

    @QueryMapping
    public boolean isValidToken(@Argument String sessionToken) {
        return true;
    }
}
