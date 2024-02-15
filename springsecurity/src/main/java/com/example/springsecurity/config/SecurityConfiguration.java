package com.example.springsecurity.config;

import com.example.springsecurity.entities.Role;
import com.example.springsecurity.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final UserService userService;
    private  final JWTAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return  new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationProvider authenticationProvider()
    {
        DaoAuthenticationProvider authenticationProvider=new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(userService.userDetailsService());
        return  authenticationProvider;
    }
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .build();
    }
    /*
     @Bean
  public AuthenticationManager authenticationManager
(AuthenticationConfiguration authenticationConfiguration) throws Exception {
return authenticationConfiguration.getAuthenticationManager ();
}
    */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws  Exception
    {
      http.csrf(AbstractHttpConfigurer::disable)
              .authorizeHttpRequests(request->request.requestMatchers("/api/v1/auth/**").permitAll()
                      .requestMatchers("/api/v1/admin").hasAnyAuthority(Role.ADMIN.name())
                      .requestMatchers("/api/v1/user").hasAnyAuthority(Role.USER.name())
                      .anyRequest().authenticated())

              .sessionManagement(manager->manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
              .authenticationProvider(authenticationProvider()).addFilterBefore(
                      jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class
              );
        return http.build();
    }
}
