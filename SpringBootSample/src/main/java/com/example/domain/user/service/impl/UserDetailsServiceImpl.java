package com.example.domain.user.service.impl;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.example.domain.user.model.MUser;
import com.example.domain.user.service.UserService;

public class UserDetailsServiceImpl implements UserDetailsService{
	@Autowired 
	@Lazy
	private UserService service;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// Get user information
		MUser loginUser = service.getLoginUser(username);
		// if the user does not exist
		if (loginUser == null) {
			throw new UsernameNotFoundException("user not found");
			
		}
		//Create authority list
		GrantedAuthority authority = new SimpleGrantedAuthority(loginUser.getRole());
		List<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(authority);
		//Generate UserDetails
		UserDetails userDetails = (UserDetails) new User(loginUser.getUserId(),
				loginUser.getPassword(),authorities);
		return userDetails;
	}
	

}
