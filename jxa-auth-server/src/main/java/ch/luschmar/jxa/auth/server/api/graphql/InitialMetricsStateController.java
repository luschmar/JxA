package ch.luschmar.jxa.auth.server.api.graphql;

import ch.luschmar.jxa.auth.server.api.graphql.output.Account;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;

@Controller
public class InitialMetricsStateController {

    @QueryMapping
    public Account account() {
        return new Account();
    }
}
