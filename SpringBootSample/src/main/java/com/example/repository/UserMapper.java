package com.example.repository;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.example.domain.user.model.MUser;

@Mapper
public interface UserMapper {
	/** User signup */
	public int insertOne(MUser user);
	
	/** Get User */
	public List<MUser> findMany(MUser user);
	
	/** Get user (1 record) */
	public MUser findOne(String userId);
	
	/** Update user */
	public void updateOne(@Param ("userId" ) String userId ,
	@Param ("password" ) String password ,
	@Param ("userName" ) String userName );
	/** Delete user */
	public int deleteOne(@Param ("userId" ) String userId );
	/** Get login user */
	public MUser findLoginUser(String userId );

}