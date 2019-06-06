package com.atguigu.shiro.handlers;

import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.atguigu.shiro.services.ShiroService;

@Controller
@RequestMapping("/shiro")
public class ShiroHandler {
	@Autowired
	private ShiroService shiroService;
	
	@RequestMapping("/testShiroAnnotation")
	public String testShiroAnnotation(HttpSession session) {
		session.setAttribute("key", "1234v");
		shiroService.testMethod();
		return "redirect:/list.jsp";
	}
	
	@RequestMapping("/login")
    public String login(@RequestParam("username")String username,@RequestParam("password")String password) {
		Subject currentUser = SecurityUtils.getSubject();
		 if (!currentUser.isAuthenticated()) {
	            UsernamePasswordToken token = new UsernamePasswordToken(username,password );
	            token.setRememberMe(true);
	            try {
	                currentUser.login(token);
	            } 
	            catch (Exception ae) {
	            	System.out.println("µÇÂ½Ê§°Ü£º "+ae.getMessage());
	            	return "redirect:/login.jsp";
	            }
	        }
    	return "redirect:/list.jsp";
    }
	
	@ExceptionHandler(UnauthorizedException.class)
	public String error(Exception e) {
		System.out.println("³öÒì³£ÁË   :"+e.getMessage());
		return "redirect:/list.jsp";
	}
}
