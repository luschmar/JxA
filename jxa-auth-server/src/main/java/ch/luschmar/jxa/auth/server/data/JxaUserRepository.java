package ch.luschmar.jxa.auth.server.data;


import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface JxaUserRepository extends CrudRepository<JxaUser, UUID> {
    Optional<JxaUser> findByEmail(String email);
}
