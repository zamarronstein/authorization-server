package mx.com.npm.authorizationserver.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.com.npm.authorizationserver.dto.CreateAppUserDto;
import mx.com.npm.authorizationserver.dto.MessageDto;
import mx.com.npm.authorizationserver.entity.AppUser;
import mx.com.npm.authorizationserver.entity.Role;
import mx.com.npm.authorizationserver.enums.RoleName;
import mx.com.npm.authorizationserver.repository.AppUserRepository;
import mx.com.npm.authorizationserver.repository.RoleRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppUserService {

    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public MessageDto createUser(CreateAppUserDto dto) {
        AppUser appUser = AppUser.builder().username(dto.username()).password(passwordEncoder.encode(dto.password())).build();
        Set<Role> roles = new HashSet<>();
        dto.roles().forEach(r -> {
            Role role = roleRepository.findByRole(RoleName.valueOf(r)).orElseThrow(() -> new RuntimeException("Role not found!"));
            roles.add(role);
        });

        appUser.setRoles(roles);
        appUserRepository.save(appUser);

        return new MessageDto("user: " + appUser.getUsername() + " saved!");
    }
}
