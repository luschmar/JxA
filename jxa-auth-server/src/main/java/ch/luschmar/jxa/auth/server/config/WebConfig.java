package ch.luschmar.jxa.auth.server.config;

import ch.luschmar.jxa.auth.server.mvc.StringToVerificationMethodConverter;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(new StringToVerificationMethodConverter());
    }
}
