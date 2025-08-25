package ch.luschmar.jxa.auth.server.api.graphql;

import ch.luschmar.jxa.auth.server.api.graphql.output.EmailBounceStatus;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;

@Controller
public class EmailBounceStatusController {

    @QueryMapping
    public EmailBounceStatus emailBounceStatus(@Argument String input) {
        return new EmailBounceStatus(false);
    }
}
