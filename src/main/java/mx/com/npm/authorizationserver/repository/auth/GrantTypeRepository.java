package mx.com.npm.authorizationserver.repository.auth;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import mx.com.npm.authorizationserver.entity.auth.GrantTypeEntity;

public interface GrantTypeRepository extends JpaRepository<GrantTypeEntity, Long> {
    Optional<GrantTypeEntity> findByGrantType(AuthorizationGrantType grantType);
}