package ch.luschmar.jxa.auth.server.mvc;

import ch.luschmar.jxa.auth.server.api.account.login.VerificationMethod;
import org.springframework.core.convert.converter.Converter;

import java.util.Optional;

public class StringToVerificationMethodConverter implements Converter<String, Optional<VerificationMethod>> {
    @Override
    public Optional<VerificationMethod> convert(String source) {
        VerificationMethod vm = null;
        try {
            vm = VerificationMethod.valueOf(source.toUpperCase());
        } catch (IllegalArgumentException e) {
        }

        return Optional.ofNullable(vm);
    }
}