package com.atguigu.shiro.services;

import java.util.Date;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.session.Session;

public class ShiroService {
	
	@RequiresRoles({"admin"})
	public void testMethod() {
		System.out.println("testmehtod ,time:"+new Date());
		Session session = SecurityUtils.getSubject().getSession();
		System.out.println("service session: "+session.getAttribute("key"));
	}
}
