package ch.luschmar.jxa.hawk;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootApplication
public class HawkTestApplication {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/hawk/**")
                .with(HawkConfigurer.hawk(), HawkConfigurer::withDefaults)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/hawk/**").hasRole("HAWKAUTHENTICATED")
                        .anyRequest().authenticated());

        return http.build();
    }

    @Bean
    public HawkKeyRepository hawkKeyRepository() {
        return new StaticKeyRepository();
    }
}
