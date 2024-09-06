package ch.luschmar.jxa.auth.server.config;

import ch.luschmar.jxa.auth.server.data.JxaUserRepository;
import ch.luschmar.jxa.auth.server.password.OnepwPasswordEncoder;
import ch.luschmar.jxa.auth.server.password.RandomComponent;
import ch.luschmar.jxa.auth.server.service.JaxUserDetailService;
import ch.luschmar.jxa.hawk.HawkConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Map;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Bean
    public UserDetailsService userDetailsService(JxaUserRepository jxaUserRepository) {
        return new JaxUserDetailService(jxaUserRepository);
    }

    @Bean
    public RandomComponent randomComponent() {
        return new RandomComponent();
    }

    @Bean
    public PasswordEncoder passwordEncoder(RandomComponent randomComponent) {
        var idForEncode = "onepw";
        return new DelegatingPasswordEncoder(idForEncode, Map.of(idForEncode, new OnepwPasswordEncoder(randomComponent)));
    }

    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/hawk/**")
                .with(HawkConfigurer.hawk(), HawkConfigurer::withDefaults)
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/hawk/**").hasRole("HAWKAUTHENTICATED")
                        .anyRequest().authenticated());

        return http.build();
    }
}
