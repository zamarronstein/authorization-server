package mx.com.npm.authorizationserver.repository.auth;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import mx.com.npm.authorizationserver.entity.auth.RedirectUriEntity;

public interface RedirectUriRepository extends JpaRepository<RedirectUriEntity, Long> {
    Optional<RedirectUriEntity> findByUri(String uri);
}