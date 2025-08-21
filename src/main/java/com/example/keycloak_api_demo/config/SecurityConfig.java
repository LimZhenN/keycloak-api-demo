package com.example.keycloak_api_demo.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {
	
	@Bean
	SecurityFilterChain security(HttpSecurity http) throws Exception {
		http
		.csrf(csrf-> csrf.disable())
		.cors(c-> c.configurationSource(corsSource())) //enable cors based on the 
		.authorizeHttpRequests(auth -> auth
				.requestMatchers("/api/public/**").permitAll()
				.requestMatchers("/api/admin/**").hasRole("ADMIN")
				.requestMatchers("/api/user/**").hasAnyRole("USER","ADMIN")
				.anyRequest().authenticated())
		.oauth2ResourceServer(o -> o.jwt(j->j.jwtAuthenticationConverter(
				keycloakRolesConverter())));
		// Get the roles from oauth server, from JWT based on the function
		// keycloakRolesConverter
		return http.build();
		}
	// Enable CORS for angular app using Spring Security (Method 1)
	@Bean
	CorsConfigurationSource corsSource() {
		CorsConfiguration cfg = new CorsConfiguration();
		cfg.setAllowedOrigins(List.of("http://localhost:4200"));
		cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		cfg.setAllowedHeaders(List.of("Authorization", "Content-Type"));
		cfg.setAllowCredentials(true);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", cfg);
		return source;
	}
	
	// COnvert JWT into information that will be used by filter / spring security
	@Bean
	Converter<Jwt, ? extends AbstractAuthenticationToken> keycloakRolesConverter() {
	    return jwt -> {
	    	// Spring security roles
	    	Collection<GrantedAuthority> authorities = new ArrayList<>();
	      
	    	// Get the roles from OAuth server / keycloak, under realm_access Map
	      Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
	      if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> roles) {
	        roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
	      }

	      // (Optional) client roles: replace "my-spa-client" if you use client roles
	      // and for each roles, add it to the info/jwt to be processed by spring security filter 
	      Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
	      // Check what is your client is your client name? change it here
	      if (resourceAccess != null && resourceAccess.get("my-spa-client") instanceof Map<?, ?> client) {
	        Object r = ((Map<?, ?>) client).get("roles");
	        if (r instanceof Collection<?> clientRoles) {
	          clientRoles.forEach(cr -> authorities.add(new SimpleGrantedAuthority("ROLE_" + cr)));
	        }
	      }

	      return new JwtAuthenticationToken(jwt, authorities, jwt.getClaimAsString("preferred_username"));
	    };
	  }

	
}

