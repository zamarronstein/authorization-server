package mx.com.npm.authorizationserver.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.com.npm.authorizationserver.dto.CreateClientDto;
import mx.com.npm.authorizationserver.dto.MessageDto;
import mx.com.npm.authorizationserver.entity.Client;
import mx.com.npm.authorizationserver.entity.auth.AuthenticationMethodEntity;
import mx.com.npm.authorizationserver.entity.auth.GrantTypeEntity;
import mx.com.npm.authorizationserver.entity.auth.RedirectUriEntity;
import mx.com.npm.authorizationserver.entity.auth.ScopeEntity;
import mx.com.npm.authorizationserver.repository.ClientRepository;
import mx.com.npm.authorizationserver.repository.auth.AuthenticationMethodRepository;
import mx.com.npm.authorizationserver.repository.auth.GrantTypeRepository;
import mx.com.npm.authorizationserver.repository.auth.RedirectUriRepository;
import mx.com.npm.authorizationserver.repository.auth.ScopeRepository;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientService implements RegisteredClientRepository {
    private final ClientRepository clientRepository;
    private final AuthenticationMethodRepository authMethodRepository;
    private final GrantTypeRepository grantTypeRepository;
    private final RedirectUriRepository redirectUriRepository;
    private final ScopeRepository scopeRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void save(RegisteredClient registeredClient) {
        // Implementación para guardar desde RegisteredClient si es necesario
    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findClientByClientId(id).orElseThrow(() -> new RuntimeException("client not found!"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findClientByClientId(clientId).orElseThrow(() -> new RuntimeException("client not found!"));
        return Client.toRegisteredClient(client);
    }

    public MessageDto create(CreateClientDto dto) {
        // Crear el cliente básico primero
        Client client = clientFromDto(dto);
        
        // Procesar métodos de autenticación
        if (dto.getAuthenticationMethods() != null && !dto.getAuthenticationMethods().isEmpty()) {
            Set<AuthenticationMethodEntity> authMethods = new HashSet<>();
            for (ClientAuthenticationMethod method : dto.getAuthenticationMethods()) {
                // Buscar si ya existe o crear uno nuevo
                AuthenticationMethodEntity entity = authMethodRepository.findByMethod(method)
                    .orElseGet(() -> {
                        AuthenticationMethodEntity newEntity = AuthenticationMethodEntity.builder()
                            .method(method)
                            .clients(new HashSet<>())
                            .build();
                        return authMethodRepository.save(newEntity);
                    });
                authMethods.add(entity);
            }
            client.setAuthenticationMethods(authMethods);
        }
        
        // Procesar tipos de concesión
        if (dto.getAuthorizationGrantTypes() != null && !dto.getAuthorizationGrantTypes().isEmpty()) {
            Set<GrantTypeEntity> grantTypes = new HashSet<>();
            for (AuthorizationGrantType type : dto.getAuthorizationGrantTypes()) {
                GrantTypeEntity entity = grantTypeRepository.findByGrantType(type)
                    .orElseGet(() -> {
                        GrantTypeEntity newEntity = GrantTypeEntity.builder()
                            .grantType(type)
                            .clients(new HashSet<>())
                            .build();
                        return grantTypeRepository.save(newEntity);
                    });
                grantTypes.add(entity);
            }
            client.setAuthorizationGrantTypes(grantTypes);
        }
        
        // Procesar URIs de redirección
        if (dto.getRedirectUris() != null && !dto.getRedirectUris().isEmpty()) {
            Set<RedirectUriEntity> redirectUris = new HashSet<>();
            for (String uri : dto.getRedirectUris()) {
                RedirectUriEntity entity = redirectUriRepository.findByUri(uri)
                    .orElseGet(() -> {
                        RedirectUriEntity newEntity = RedirectUriEntity.builder()
                            .uri(uri)
                            .clients(new HashSet<>())
                            .build();
                        return redirectUriRepository.save(newEntity);
                    });
                redirectUris.add(entity);
            }
            client.setRedirectUris(redirectUris);
        }
        
        // Procesar scopes
        if (dto.getScopes() != null && !dto.getScopes().isEmpty()) {
            Set<ScopeEntity> scopes = new HashSet<>();
            for (String scope : dto.getScopes()) {
                ScopeEntity entity = scopeRepository.findByName(scope)
                    .orElseGet(() -> {
                        ScopeEntity newEntity = ScopeEntity.builder()
                            .name(scope)
                            .clients(new HashSet<>())
                            .build();
                        return scopeRepository.save(newEntity);
                    });
                scopes.add(entity);
            }
            client.setScopes(scopes);
        }
        
        // Guardar el cliente con todas sus relaciones
        clientRepository.save(client);
        
        return new MessageDto("client " + dto.getClientId() + " has been saved!");
    }

    private Client clientFromDto(CreateClientDto dto) {
        return Client.builder()
                .clientId(dto.getClientId())
                .clientSecret(passwordEncoder.encode(dto.getClientSecret()))
                .requireProofKey(dto.isRequireProofKey())
                .build();
    }
}