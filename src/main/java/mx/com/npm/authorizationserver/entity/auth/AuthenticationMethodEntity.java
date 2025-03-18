package mx.com.npm.authorizationserver.entity.auth;

import java.util.Set;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import mx.com.npm.authorizationserver.entity.Client;

@Entity
@Table(name = "authentication_methods")
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class AuthenticationMethodEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true)
    private ClientAuthenticationMethod method;
    
    @ManyToMany(mappedBy = "authenticationMethods")
    private Set<Client> clients;
}