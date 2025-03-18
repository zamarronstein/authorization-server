package mx.com.npm.authorizationserver.repository.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import mx.com.npm.authorizationserver.entity.auth.AuthenticationMethodEntity;
import java.util.Optional;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;


public interface AuthenticationMethodRepository extends JpaRepository<AuthenticationMethodEntity, Long>{
    Optional<AuthenticationMethodEntity> findByMethod(ClientAuthenticationMethod method);
}
