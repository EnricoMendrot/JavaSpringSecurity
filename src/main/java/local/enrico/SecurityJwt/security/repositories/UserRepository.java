package local.enrico.SecurityJwt.security.repositories;

import local.enrico.SecurityJwt.security.entites.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 *
 * @author Enrico
 */

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional <User> findByEmail(String email);
}
