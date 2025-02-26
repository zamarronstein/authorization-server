package mx.com.npm.authorizationserver;

import mx.com.npm.authorizationserver.entity.Role;
import mx.com.npm.authorizationserver.enums.RoleName;
import mx.com.npm.authorizationserver.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthorizationServerApplication /*implements CommandLineRunner*/ {

/*
	@Autowired
	RoleRepository roleRepository;
*/

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerApplication.class, args);
	}

/*
	@Override
	public void run(String... args) throws Exception {
		Role roleAdmin = Role.builder().role(RoleName.ROLE_ADMIN).build();
		Role roleStudent = Role.builder().role(RoleName.ROLE_STUDENT).build();
		Role roleParent = Role.builder().role(RoleName.ROLE_PARENT).build();

		roleRepository.save(roleAdmin);
		roleRepository.save(roleStudent);
		roleRepository.save(roleParent);
	}
*/
}
