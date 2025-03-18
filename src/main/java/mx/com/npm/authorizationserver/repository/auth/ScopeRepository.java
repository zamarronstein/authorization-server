package mx.com.npm.authorizationserver.repository.auth;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import mx.com.npm.authorizationserver.entity.auth.ScopeEntity;

public interface ScopeRepository extends JpaRepository<ScopeEntity, Long> {
    Optional<ScopeEntity> findByName(String name);
}