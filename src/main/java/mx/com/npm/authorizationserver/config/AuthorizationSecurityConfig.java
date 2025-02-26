package mx.com.npm.authorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.com.npm.authorizationserver.service.ClientService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Clase de configuración para establecer este servicio como servidor de autorización
 * */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class AuthorizationSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final ClientService clientService;

    /**
     * URL del servidor de autorización
     * */
    @Value("${spring.security.oauth2.client.provider.spring.issuer-uri}")
    private String issuerUri;

    /**
     * URL a la que redirecciona en caso de éxito
     * */
    @Value("${security.redirect-uri}")
    private String redirectUri;

    /**
     * Configuración de la cadena de filtros de seguridad para la autenticación.
     * Esta función establece la configuración de seguridad para el servidor de autorización OAuth2.
     * Se aplica la configuración predeterminada de seguridad del servidor de autorización.
     * Se configura el proveedor de identidad OpenID Connect (OIDC) con valores predeterminados.
     * Se maneja la excepción de autenticación estableciendo un punto de entrada de autenticación con una URL de inicio de sesión personalizada.
     * Además, se configura el servidor de recursos OAuth2 para validar tokens JWT (JSON Web Token) con los valores predeterminados.
     * La función devuelve la cadena de filtros de seguridad configurada.
     *
     * @param http Configuración de seguridad de HTTP.
     * @return SecurityFilterChain configurado para la autenticación.
     * @throws Exception Si hay algún error durante la configuración.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults())
        ;

        http.exceptionHandling(exception -> exception
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    /**
     * Configuración de la cadena de filtros de seguridad para las solicitudes web.
     * Todas las solicitudes deben estar autenticadas para acceder.
     * Se utiliza el formulario de inicio de sesión con la configuración predeterminada.
     *
     * @param http Configuración de seguridad de HTTP.
     * @return SecurityFilterChain configurado para las solicitudes web.
     * @throws Exception Si hay algún error durante la configuración.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.requestMatchers("/auth/**", "/client/**").permitAll().anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        http.csrf(csrf -> csrf.ignoringRequestMatchers("/auth/**", "/client/**"));
        return http.build();
    }

    /**
     * Configuración de las configuraciones del servidor de autorización.
     * Se establece la URI del emisor (issuer URI) para el servidor de autorización.
     *
     * @return AuthorizationServerSettings configurado con la URI del emisor.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer(this.issuerUri).build();
    }

    /**
     * Configuración del decodificador JWT.
     * Utiliza la configuración predeterminada del servidor de autorización OAuth2.
     *
     * @param jwkSource Fuente de claves JSON Web Key (JWK) con contexto de seguridad.
     * @return JwtDecoder configurado utilizando la fuente de claves JWK proporcionada.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Personalizador de tokens OAuth2 para codificación JWT.
     * Este personalizador agrega información adicional a los tokens JWT según el tipo de token.
     * Para los tokens "id_token", agrega el reclamo "token_type" con el valor "id token" y configura el emisor.
     * Para los tokens "access_token", agrega los reclamos "token_type", "roles" y "username" con información del principal y configura el emisor.
     *
     * @return OAuth2TokenCustomizer personalizado para ajustar los tokens JWT.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer () {
        return context -> {
            Authentication principal = context.getPrincipal();
            if (context.getTokenType().getValue().equals("id_token")) {
                context.getClaims().claim("token_type", "id token");
                context.getClaims().issuer(this.issuerUri);
            }

            if (context.getTokenType().getValue().equals("access_token")) {
                context.getClaims().claim("token_type", "access token");
                Set<String> roles = principal.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims().claim("roles", roles).claim("username", principal.getName());
                context.getClaims().issuer(this.issuerUri);
            }
        };
    }

    /**
     * Fuente de claves JSON Web Key (JWK) para el decodificador JWT.
     * Genera un conjunto JWK con una clave RSA y proporciona una implementación de JWKSource.
     *
     * @return JWKSource configurado con una clave RSA.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRSAKey();
        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    /**
     * Genera una clave RSA para su uso en el conjunto JWK.
     *
     * @return RSAKey generado con una clave pública y privada.
     */
    private RSAKey generateRSAKey() {
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    /**
     * Genera un par de claves RSA para su uso en la clave JWK.
     *
     * @return KeyPair generado con una clave pública y privada.
     */
    private KeyPair generateKeyPair() {
        KeyPair keyPair;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        }catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }

        return keyPair;
    }
}
