package ch.luschmar.jxa.hawk;

import ch.luschmar.jxa.crypto.hawk.HawkHeader;
import ch.luschmar.jxa.crypto.hawk.HawkHeaderConverter;
import ch.luschmar.jxa.crypto.hawk.HawkPayload;
import ch.luschmar.jxa.crypto.hawk.HawkPayloadConverter;
import ch.luschmar.jxa.http.CachedBodyHttpServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNullElse;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.util.StringUtils.startsWithIgnoreCase;

public class HawkAuthenticationConverter implements AuthenticationConverter {
    private static final Logger LOG = LoggerFactory.getLogger(HawkAuthenticationConverter.class);
    public static final String HAWK_PREFIX = "Hawk ";
    private final HawkKeyRepository keyRepository;
    private final HawkPayloadConverter hawkPayloadConverter = new HawkPayloadConverter();
    private final HawkHeaderConverter hawkHeaderConverter = new HawkHeaderConverter();
    private final boolean timeCheck;

    public HawkAuthenticationConverter(HawkKeyRepository keyRepository, boolean timeCheck) {
        this.keyRepository = keyRepository;
        this.timeCheck = timeCheck;
    }

    /**
     * @param inRequest CachedBodyHttpServletRequest; because this converter consumes the content
     * @return valid authentication or null
     * @throws BadCredentialsException  on error in hawk-header or hawk-payload
     * @throws UncheckedIOException     misreading in content
     * @throws IllegalArgumentException inRequest must be a CachedBodyHttpServletRequest
     */
    @Override
    public Authentication convert(HttpServletRequest inRequest) {
        if (inRequest instanceof CachedBodyHttpServletRequest request) {
            final var header = request.getHeader(AUTHORIZATION);
            if (!hasText(header)) {
                return null;
            }
            var trimmedHeader = header.trim();
            if (!startsWithIgnoreCase(trimmedHeader, HAWK_PREFIX)) {
                return null;
            }

            var hawkRawHeader = trimmedHeader.substring(HAWK_PREFIX.length());
            var hawkParameter = Arrays.stream(hawkRawHeader.split(",")).map(s -> s.split("=", 2))
                    .filter(a -> a.length == 2)
                    .map(b -> new AbstractMap.SimpleEntry<>(b[0].trim(), removeQuotes(b[1].trim())))
                    .collect(Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue));

            var ts = Long.parseLong(hawkParameter.getOrDefault("ts", "0"));
            var parsedTs = Instant.ofEpochSecond(ts);

            if (!timeCheck) {
                LOG.error("Time-Check disabled! DO NOT USE IN PRODUCTION!!!");
            } else {
                var now = Instant.now();
                if (now.plus(5, ChronoUnit.SECONDS).isAfter(parsedTs) || now.minus(5, ChronoUnit.SECONDS).isBefore(parsedTs)) {
                    throw new BadCredentialsException("Ts invalid");
                }
            }

            var hawkHeader = new HawkHeader(parsedTs,
                    hawkParameter.getOrDefault("nonce", ""),
                    request.getMethod(),
                    extractURIWithQuery(request),
                    request.getHeader(HOST).split(":")[0],
                    Integer.parseInt(request.getHeader(HOST).split(":")[1]),
                    hawkParameter.getOrDefault("hash", ""),
                    hawkParameter.getOrDefault("ext", ""),
                    null);

            if (hasText(hawkHeader.hash())) {
                try (var inputStream = request.getInputStream()) {
                    var hawkPayload = new HawkPayload(request.getContentType(),
                            new String(StreamUtils.copyToByteArray(inputStream), StandardCharsets.UTF_8));
                    hawkHeader.withPayload(hawkPayload);
                    var sha256 = hawkPayloadConverter.apply(hawkPayload);
                    if (!hawkHeader.hash().equals(sha256)) {
                        throw new BadCredentialsException("Hash is incorrect");
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException("Invalid request body data", e);
                }
            }

            var key = keyRepository.findKeyById(hawkParameter.get("id"));
            var calculatedMac = hawkHeaderConverter.apply(hawkHeader, key);
            if (!hawkParameter.getOrDefault("mac", "").equals(calculatedMac)) {
                throw new BadCredentialsException("Mac is incorrect");
            }
            return new HawkAuthenticationToken(hawkParameter.get("id"));
        }
        throw new IllegalArgumentException("Converter consumes request content; a CachedBodyHttpServletRequest is required");
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
