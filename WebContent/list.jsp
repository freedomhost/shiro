<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags"%>    
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
	<h3>List Page</h3>
	<br><br>
	Welcome: <shiro:principal></shiro:principal>
	<br><br>
	<a href="/shiro-2/admin.jsp">Admin Page</a>
	<br><br>
    <a href="/shiro-2/user.jsp">User Page</a>	
	<br><br>
	<a href="/shiro-2/shiro/testShiroAnnotation">Test ShiroAnnotation</a>
	<br><br>
	<a href="/shiro-2/shiro/logout">Logout</a>	
	
</body>
</html>