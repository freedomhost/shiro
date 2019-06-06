package com.atguigu.shiro.realms;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.realm.AuthorizingRealm;


public class SecondRealm extends AuthorizingRealm{
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		System.out.println("SecondRealm doGetAuthenticationInfo...");
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		String username = upToken.getUsername();
		System.out.println("从数据库中获取username: "+username+" 所对应的信息");
		if("unknown".equals(username)) {
			throw new UnknownAccountException("用户不存在!");
		}
		if("monster".equals(username)) {
			throw new LockedAccountException("用户被锁定");
		}
		Object credentials = null;
		if("admin".equals(username)) {
			credentials = "ce2f6417c7e1d32c1d81a797ee0b499f87c5de06";
		}
		if("user".equals(username)) {
			credentials = "073d4c3ae812935f23cb3f2a71943f49e082a718";
		}
		Object principal = username;
		
		String realmName = getName();
		SimpleAuthenticationInfo info = null;
		ByteSource credentialsSalt = ByteSource.Util.bytes(username);
		info = new SimpleAuthenticationInfo(principal, credentials, credentialsSalt, realmName);
		
		return info;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		return null;
	}

	public static void main(String[] args) {
		String hashAlgorithmName = "SHA1";
		Object credentials = "123456";
		int hashIterations = 1024;
		ByteSource credentialsSalt = ByteSource.Util.bytes("user");
		Object result = new SimpleHash(hashAlgorithmName, credentials,credentialsSalt, hashIterations);
		System.out.println(result);
	}
}
