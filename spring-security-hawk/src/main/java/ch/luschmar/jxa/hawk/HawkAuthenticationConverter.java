package ch.luschmar.jxa.hawk;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNullElse;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class HawkAuthenticationConverter implements AuthenticationConverter {
    public static final String HAWK_PREFIX = "Hawk ";
    private final HawkKeyRepository keyRepository;

    public HawkAuthenticationConverter(HawkKeyRepository keyRepository) {
        this.keyRepository = keyRepository;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        var header = request.getHeader(AUTHORIZATION);
        if (header == null) {
            return null;
        }
        header = header.trim();
        if (!StringUtils.startsWithIgnoreCase(header, HAWK_PREFIX)) {
            return null;
        }

        header = header.substring(HAWK_PREFIX.length());
        var hawkParameter = Arrays.stream(header.split(",")).map(s -> s.split("=", 2))
                .filter(a -> a.length == 2)
                .map(b -> new AbstractMap.SimpleEntry<>(b[0].trim(), removeQuotes(b[1].trim())))
                .collect(Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue));

        var cred = new HawkCredentials(hawkParameter.get("id"),
                hawkParameter.getOrDefault("ts", ""),
                hawkParameter.getOrDefault("nonce", ""),
                request.getMethod(),
                extractURIWithQuery(request),
                request.getHeader("Host").split(":")[0],
                Integer.parseInt(request.getHeader("Host").split(":")[1]),
                hawkParameter.getOrDefault("hash", ""),
                hawkParameter.getOrDefault("ext", ""),
                hawkParameter.getOrDefault("mac", ""));

        try {
            var key = keyRepository.findKeyById(hawkParameter.get("id"));
            var secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            var encodedHash = mac.doFinal(cred.toHawkBytes());
            var str = Base64.getEncoder().encodeToString(encodedHash);

            if (!hawkParameter.getOrDefault("mac", "").equals(str)) {
                throw new BadCredentialsException("Hash is incorrect");
            }
            return new HawkAuthenticationToken(cred);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new BadCredentialsException("Something went wrong", e);
        }
    }

    String extractURIWithQuery(HttpServletRequest request) {
        var query = requireNonNullElse(request.getQueryString(), "");
        if (!query.isBlank()) {
            query = "?" + query;
        }
        return request.getRequestURI() + query;
    }

    static String removeQuotes(String quotedString) {
        return requireNonNullElse(quotedString, "").replaceAll("^\"|\"$", "");
    }
}
