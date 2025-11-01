package ch.luschmar.jxa.auth.server.api.reverse;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.cloud.gateway.mvc.ProxyExchange;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

@RestController
public class GraphqlSplitterController {
    @PostMapping(path = {"/graphql", "/graphql/**"})
    public ResponseEntity<?> reverse(ProxyExchange<byte[]> proxy, HttpServletRequest request, @RequestHeader("Authorization") String authorization, @RequestBody List<WrappedGraphQlRequest> requests) {
        System.out.println(authorization);
        var results = requests.stream()
                .map(r -> new String(requireNonNull(proxy.header("X-FXA-AUTH", authorization).body(r.body()).uri("http://localhost:" + request.getServerPort() + "/api/graphql" + proxy.path("/graphql"))
                        .post().getBody())))
                .collect(Collectors.joining(","));

        return ResponseEntity.ok(String.format("[%s]", results));
    }
}
