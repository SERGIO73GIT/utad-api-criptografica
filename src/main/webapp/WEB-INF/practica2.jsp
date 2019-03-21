<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
	<h1>HASHES </h1>
	<table>
		<tr><td>
			<input size="40" readonly="true" value="${md5}"></input>
		</td></tr>
		<tr><td>
			<input size="50" readonly="true" value="${sha1}"></input>
		</td></tr>
		<tr><td>
			<input size="100" readonly="true" value="${sha2}"></input>
		</td></tr>
		<tr><td>	
			<input size="140" readonly="true" value="${sha3}"></input>
		</td></tr>
		
	</table>
</body>
</html>