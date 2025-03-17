package ch.luschmar.jxa.hawk;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootApplication
public class HawkTestApplication {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf
                        .ignoringRequestMatchers("/**")
                ).securityMatcher("/**")

                .with(HawkConfigurer.hawk().disableTimeCheck(), HawkConfigurer::withDefaults)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/**").hasRole("HAWK_AUTHENTICATED")
                        .anyRequest().authenticated());

        return http.build();
    }

    @Bean
    public HawkKeyRepository hawkKeyRepository() {
        return new StaticKeyRepository();
    }
}
