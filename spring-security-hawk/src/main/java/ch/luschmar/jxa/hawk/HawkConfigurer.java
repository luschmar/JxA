package ch.luschmar.jxa.hawk;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.Objects;


public class HawkConfigurer extends AbstractHttpConfigurer<HawkConfigurer, HttpSecurity> {
    private HawkKeyRepository keyRepository;
    private AuthenticationEntryPoint authenticationEntryPoint;


    @Override
    public void init(HttpSecurity http) {
        // no other entryPoints defined
        keyRepository = new StaticKeyRepository();
        authenticationEntryPoint = new HawkAuthenticationEntryPoint();
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        var authenticationManager = http.getSharedObject(AuthenticationManager.class);
        var hawkAuthenticationFilter = new HawkAuthenticationFilter(authenticationManager,
                authenticationEntryPoint,
                Objects.requireNonNull(this.keyRepository, ""));

        http.addFilterBefore(hawkAuthenticationFilter, BasicAuthenticationFilter.class);
    }

    public HawkConfigurer keyRepository(HawkKeyRepository keyRepository) {
        this.keyRepository = keyRepository;
        return this;
    }

    public HawkConfigurer authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    public HawkConfigurer withDefaults() {
        return this;
    }

    public static HawkConfigurer hawk() {
        return new HawkConfigurer();
    }
}
