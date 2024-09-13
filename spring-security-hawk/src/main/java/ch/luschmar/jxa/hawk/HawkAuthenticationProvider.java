package ch.luschmar.jxa.hawk;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class HawkAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof HawkAuthenticationToken hat) {
            final List<GrantedAuthority> grantedAuths = new ArrayList<>();
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_HAWKAUTHENTICATED"));
            final UserDetails principal = new User("name", "password", grantedAuths);
            return new UsernamePasswordAuthenticationToken(principal, "password", grantedAuths);
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authClass) {
        return authClass.equals(HawkAuthenticationToken.class);
    }
}
