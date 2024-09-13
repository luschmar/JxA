package ch.luschmar.jxa.hawk;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class HawkAuthenticationFilter extends OncePerRequestFilter {
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    private final AuthenticationConverter authenticationConverter;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private final RememberMeServices rememberMeServices = new NullRememberMeServices();
    private boolean ignoreFailure = false;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    public HawkAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint, HawkKeyRepository keyRepository) {
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.authenticationConverter = new HawkAuthenticationConverter(keyRepository);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            var auth = this.authenticationConverter.convert(request);
            // No Hawk authentication
            if (auth == null) {
                filterChain.doFilter(request, response);
                return;
            }
            String username = auth.getName();
            if (authenticationIsRequired(username)) {
                var authResult = authenticationManager.authenticate(auth);
                var context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authResult);
                securityContextHolderStrategy.setContext(context);

                rememberMeServices.loginSuccess(request, response, authResult);
                securityContextRepository.saveContext(context, request, response);
                onSuccessfulAuthentication(request, response, authResult);
            }
        } catch (AuthenticationException e) {
            securityContextHolderStrategy.clearContext();

            rememberMeServices.loginFail(request, response);
            onUnsuccessfulAuthentication(request, response, e);
            if (!this.ignoreFailure) {
                authenticationEntryPoint.commence(request, response, e);
            }
        }
        filterChain.doFilter(request, response);
    }

    protected boolean authenticationIsRequired(String username) {
        // Only reauthenticate if username doesn't match SecurityContextHolder and user
        // isn't authenticated (see SEC-53)
        var existingAuth = securityContextHolderStrategy.getContext().getAuthentication();
        if (existingAuth == null || !existingAuth.getName().equals(username) || !existingAuth.isAuthenticated()) {
            return true;
        }
        // Handle unusual condition where an AnonymousAuthenticationToken is already
        // present. This shouldn't happen very often, as BasicAuthenticationFilter is
        // meant to
        // be earlier in the filter chain than AnonymousAuthenticationFilter.
        // Nevertheless, presence of both an AnonymousAuthenticationToken together with a
        // BASIC authentication request header should indicate reauthentication using the
        // BASIC protocol is desirable. This behaviour is also consistent with that
        // provided by form and digest, both of which force re-authentication if the
        // respective header is detected (and in doing so replace/ any existing
        // AnonymousAuthenticationToken). See SEC-610.
        return (existingAuth instanceof AnonymousAuthenticationToken);
    }


    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              Authentication authResult) throws IOException {
    }

    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationException failed) throws IOException {
    }
}
