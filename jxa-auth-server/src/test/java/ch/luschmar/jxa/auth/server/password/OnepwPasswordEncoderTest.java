package ch.luschmar.jxa.auth.server.password;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OnepwPasswordEncoderTest {

    @Mock
    RandomComponent randomComponent;

    @InjectMocks
    OnepwPasswordEncoder onepwPasswordEncoder;

    @Test
    void encode() {
        when(randomComponent.nextAuthSalt()).thenReturn(Hex.decode("00f0000000000000000000000000000000000000000000000000000000000000"));
        var verifyHash = onepwPasswordEncoder.encode("247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375");
        assertEquals("00f0000000000000000000000000000000000000000000000000000000000000:a4765bf103dc057f4cf4bc2c131ddb6716e8a4333cc55e1d3c449f31f0eec4f1", verifyHash);
    }

    @Test
    void matches() {
        assertTrue(onepwPasswordEncoder.matches("247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375",
                "00f0000000000000000000000000000000000000000000000000000000000000:a4765bf103dc057f4cf4bc2c131ddb6716e8a4333cc55e1d3c449f31f0eec4f1"));
    }
}