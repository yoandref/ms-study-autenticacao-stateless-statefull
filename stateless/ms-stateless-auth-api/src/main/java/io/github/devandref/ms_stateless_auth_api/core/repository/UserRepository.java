package io.github.devandref.ms_stateless_auth_api.core.repository;

import io.github.devandref.ms_stateless_auth_api.core.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByUsername(String username);

}
