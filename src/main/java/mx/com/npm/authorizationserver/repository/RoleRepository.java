package mx.com.npm.authorizationserver.repository;

import mx.com.npm.authorizationserver.entity.Role;
import mx.com.npm.authorizationserver.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByRole(RoleName roleName);
}
