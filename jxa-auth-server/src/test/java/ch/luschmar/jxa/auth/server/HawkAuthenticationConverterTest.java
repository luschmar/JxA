package ch.luschmar.jxa.auth.server;

import ch.luschmar.jxa.hawk.HawkAuthenticationConverter;
import ch.luschmar.jxa.hawk.HawkAuthenticationToken;
import ch.luschmar.jxa.hawk.HawkKeyRepository;
import ch.luschmar.jxa.hawk.StaticKeyRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class HawkAuthenticationConverterTest {
    @Spy
    HawkKeyRepository hawkKeyRepository = new StaticKeyRepository();
    @InjectMocks
    HawkAuthenticationConverter converter;

    /**
     * @see <a href="https://github.com/mozilla/hawk/blob/0b684f4/API.md#protocol-example">Protocol Example</a>
     */
    @Test
    void name() {
        var request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/resource/1");
        request.setQueryString("b=1&a=2");

        request.addHeader("Authorization", "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", ext=\"some-app-ext-data\", mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\"");
        request.addHeader("Host", "example.com:8000");

        var auth = converter.convert(request);

        var credentialObject = (HawkAuthenticationToken) auth.getCredentials();
        assertEquals("dh37fgj492je", credentialObject.getCredentials());
    }
}