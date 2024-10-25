package com.tkk.recruitment.config;

import com.tkk.recruitment.service.MyUserDetailService;
import com.tkk.recruitment.webtoken.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final MyUserDetailService myUserDetailService;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfiguration(MyUserDetailService myUserDetailService, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.myUserDetailService = myUserDetailService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(registry -> {
                    // allows all users to access "/home" endpoint
                    registry.requestMatchers("/home", "/register/**", "/authenticate").permitAll();
                    // Restricts "/admin/**" endpoints to users with "ADMIN" role
                    registry.requestMatchers("/admin/**").hasRole("ADMIN");
                    // Restricts "/user/**" endpoints to users with "USER" role
                    registry.requestMatchers("/user/**").hasRole("USER");
                    // Requires authentication for all other requests
                    registry.anyRequest().authenticated();
                })
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .formLogin(httpSecurityFormLoginConfigurer ->
//                        httpSecurityFormLoginConfigurer
//                                .loginPage("/login")
//                                .successHandler(new AuthenticationSuccessHandler())
//                                .permitAll()
//
//                )
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return myUserDetailService;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(myUserDetailService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(authenticationProvider());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
