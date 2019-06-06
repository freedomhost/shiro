package com.atguigu.shiro.realms;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;


public class ShiroRealm extends AuthorizingRealm{
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		System.out.println("FirstRealm doGetAuthenticationInfo...");
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
			credentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		}
		Object principal = username;
		
		String realmName = getName();
		System.out.println("realmName: "+realmName);
		SimpleAuthenticationInfo info = null;
		ByteSource credentialsSalt = ByteSource.Util.bytes(username);
		info = new SimpleAuthenticationInfo(principal, credentials, credentialsSalt, realmName); 
		return info;
	}
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		System.out.println("doGetAuthorizationInfo...");
		Object principal = principals.getPrimaryPrincipal();
		Set<String> roles = new HashSet<>();
		roles.add("user");
		if("admin".equals(principal)) {
			roles.add("admin");
		}
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roles);
		return info;
	}
	public static void main(String[] args) {
		String hashAlgorithmName = "MD5";
		Object credentials = "123456";
		int hashIterations = 1024;
		ByteSource credentialsSalt = ByteSource.Util.bytes("admin");
		Object result = new SimpleHash(hashAlgorithmName, credentials,credentialsSalt, hashIterations);
		System.out.println(result);
	}
}
