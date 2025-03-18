package mx.com.npm.authorizationserver.entity.auth;

import java.util.Set;

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
@Table(name = "redirect_uris")
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class RedirectUriEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true)
    private String uri;
    
    @ManyToMany(mappedBy = "redirectUris")
    private Set<Client> clients;
}