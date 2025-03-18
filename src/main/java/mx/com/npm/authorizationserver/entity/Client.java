package mx.com.npm.authorizationserver.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import mx.com.npm.authorizationserver.entity.auth.AuthenticationMethodEntity;
import mx.com.npm.authorizationserver.entity.auth.GrantTypeEntity;
import mx.com.npm.authorizationserver.entity.auth.RedirectUriEntity;
import mx.com.npm.authorizationserver.entity.auth.ScopeEntity;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinColumns;

import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String clientId;
    private String clientSecret;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "client_authentication_methods", joinColumns = @JoinColumn(name = "client_id"), inverseJoinColumns = @JoinColumn(name = "auth_method_id"))
    private Set<AuthenticationMethodEntity> authenticationMethods;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "client_grant_types", joinColumns = @JoinColumn(name = "client_id"), inverseJoinColumns = @JoinColumn(name = "grant_type_id"))
    private Set<GrantTypeEntity> authorizationGrantTypes;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "client_redirect_uris", joinColumns = @JoinColumn(name = "client_id"), inverseJoinColumns = @JoinColumn(name = "redirect_uri_id"))
    private Set<RedirectUriEntity> redirectUris;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "client_scopes", joinColumns = @JoinColumn(name = "client_id"), inverseJoinColumns = @JoinColumn(name = "scope_id"))
    private Set<ScopeEntity> scopes;

    private boolean requireProofKey;

    public static RegisteredClient toRegisteredClient(Client client) {
        RegisteredClient.Builder builder = RegisteredClient.withId(client.getClientId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientIdIssuedAt(new Date().toInstant())
                .clientAuthenticationMethods(am -> 
                    am.addAll(client.getAuthenticationMethods().stream()
                        .map(AuthenticationMethodEntity::getMethod)
                        .collect(Collectors.toSet())))
                .authorizationGrantTypes(agt -> 
                    agt.addAll(client.getAuthorizationGrantTypes().stream()
                        .map(GrantTypeEntity::getGrantType)
                        .collect(Collectors.toSet())))
                .redirectUris(ru -> 
                    ru.addAll(client.getRedirectUris().stream()
                        .map(RedirectUriEntity::getUri)
                        .collect(Collectors.toSet())))
                .scopes(s -> 
                    s.addAll(client.getScopes().stream()
                        .map(ScopeEntity::getName)
                        .collect(Collectors.toSet())))
                .clientSettings(ClientSettings.builder().requireProofKey(client.isRequireProofKey()).build());

        return builder.build();
    }
}
