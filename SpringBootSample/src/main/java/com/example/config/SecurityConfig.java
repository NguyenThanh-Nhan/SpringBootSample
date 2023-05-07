package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.domain.user.service.impl.UserDetailsServiceImpl;

@Configuration
public class SecurityConfig {
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		// Do not apply security
		http.authorizeHttpRequests().requestMatchers("/login").permitAll().requestMatchers("/user/signup").permitAll().requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
				.anyRequest().authenticated();

		http.headers(headers -> headers.frameOptions().disable());
		http.authenticationProvider(authenticationProvider());
		//login process
		http.formLogin().loginProcessingUrl("/login").loginPage("/login").failureUrl("/login?error")
				.usernameParameter("userId").passwordParameter("password").defaultSuccessUrl("/user/list", true);
		// logout process
		http
		.logout()
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
		.logoutUrl("/logout")
		.logoutSuccessUrl("/login?logout");
		//disable CSRF measures (temporary)
//		http.csrf().disable();
		return http.build();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		// Set of login unnecessary page
		return (web) -> web.ignoring().requestMatchers("/webjars/**").requestMatchers("/css/**")
				.requestMatchers("/js/**").requestMatchers(new AntPathRequestMatcher("/h2-console/**"));
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public UserDetailsService userDetailsService() {
//		UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("admin")).roles("ADMIN")
//				.build();
//		UserDetails user = User.withUsername("user").password(passwordEncoder().encode("user")).roles("USER").build();
//		return new InMemoryUserDetailsManager(admin, user);
		return new UserDetailsServiceImpl();
	}
}
