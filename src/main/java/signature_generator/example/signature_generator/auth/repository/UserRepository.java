package signature_generator.example.signature_generator.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import signature_generator.example.signature_generator.auth.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // Existing methods
    User findByEmail(String email);
    User findByVerificationToken(String token);

    Optional<User> findByUsername(String username);// <-- Add this line
}