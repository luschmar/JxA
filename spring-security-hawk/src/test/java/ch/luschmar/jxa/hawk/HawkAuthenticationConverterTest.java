package ch.luschmar.jxa.hawk;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertFalse;

class HawkAuthenticationConverterTest {
    @Nested
    class Tools {
        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {
                "\"\"",
                "\"asdf\"",
                "\"as\"df\""
        })
        void removeQuotes(String source) {
            var result = HawkAuthenticationConverter.removeQuotes(source);

            assertFalse(result.startsWith("\""));
            assertFalse(result.endsWith("\""));
        }
    }
}