package ch.luschmar.jxa.auth.server.data;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface JxaSessionRepository extends CrudRepository<JxaSession, UUID> {
}
