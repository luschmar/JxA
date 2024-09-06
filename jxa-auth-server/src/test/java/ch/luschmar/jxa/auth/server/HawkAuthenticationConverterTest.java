package ch.luschmar.jxa.auth.server;

import ch.luschmar.jxa.hawk.HawkAuthenticationConverter;
import ch.luschmar.jxa.hawk.HawkCredentials;
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

    @Test
    void name() {
        var request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setPathInfo("/resource/1?b=1&a=2");

        request.addHeader("Authorization", "Hawk id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", ext=\"some-app-ext-data\", mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\"");
        request.addHeader("Host", "example.com:8000");

        var auth = converter.convert(request);

        var credentialObject = (HawkCredentials) auth.getCredentials();
        assertEquals("dh37fgj492je", credentialObject.keyId());
        assertEquals("1353832234", credentialObject.timestamp());
        assertEquals("j4h3g2", credentialObject.nonce());
        assertEquals("some-app-ext-data", credentialObject.ext());
        assertEquals("6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=", credentialObject.mac());
    }
}