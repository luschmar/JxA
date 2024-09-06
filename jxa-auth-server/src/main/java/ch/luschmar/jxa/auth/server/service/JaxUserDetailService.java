package ch.luschmar.jxa.auth.server.service;

import ch.luschmar.jxa.auth.server.data.JxaUserRepository;
import ch.luschmar.jxa.auth.server.password.OnepwPasswordEncoder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class JaxUserDetailService implements UserDetailsService {
    private final JxaUserRepository jxaUserRepository;

    public JaxUserDetailService(JxaUserRepository jxaUserRepository) {
        this.jxaUserRepository = jxaUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = jxaUserRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException(""));
        var onepw = new OnepwPasswordEncoder.OnePw(user.getAuthSalt(), user.getVerifyHash());
        return User.withUsername(user.getEmail()).password("{onepw}" + onepw).build();
    }
}
