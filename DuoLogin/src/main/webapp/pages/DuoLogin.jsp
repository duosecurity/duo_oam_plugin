<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<%@ page contentType="text/html;charset=windows-1252"%>
<%@ page import="oracle.security.am.common.utilities.constant.GenericConstants"%>
<html>
    <head>
        <title>Duo Authentication</title>
        <meta http-equiv="Content-Type" content="text/html; charset=windows-1252"/>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="<%=request.getContextPath()%>/pages/css/DuoWeb.css" rel="stylesheet">
    </head>
    <body>
        <%
        // A note about request.getContextPath() that is used in this page.
        // This function returns the 'context root' value set up in
        // the admin panel. This should match the root folder name of the
        // project in order to generate the correct path for the resources

        // GenericConstants.PLUGIN_CLIENT_RESPONSE returns a comma separated
        // String of key value pairs. eg: "key1=value1,key2=value2"
        // Because the SIG_REQUEST value has equal signs in it we must parse
        // the first key-value by the first equal sign we encounter.
        final String SIG_REQUEST = request.getParameter(
                GenericConstants.PLUGIN_CLIENT_RESPONSE).split("=", 2)[1];
        final String API_KEY_VALUE = request.getParameter(
                GenericConstants.PLUGIN_CLIENT_RESPONSE).split(",")[1];
        final String API_HOSTNAME = API_KEY_VALUE.split("=")[1];
        final String reqToken = request.getParameter(GenericConstants.AM_REQUEST_TOKEN_IDENTIFIER);
        final String reqId = request.getParameter("request_id");
        %>
        <h1>Duo Authentication</h1>
        <script src="<%=request.getContextPath()%>/pages/js/Duo-Web-v2.min.js" type="text/javascript"></script>
        <iframe id="duo_iframe" frameborder="0"></iframe>
        <form id="duo_form">
          <%
          if(reqToken != null && reqToken.length() > 0) { %>
          <input type="hidden" name="<%=GenericConstants.AM_REQUEST_TOKEN_IDENTIFIER%>" value="<%=reqToken%>">
          <%
          }
          %>
          <%
          if(reqId != null && reqId.length() > 0) { %>
          <input type="hidden" name="request_id" value="<%=reqId%>">
          <%
          }
          %>
        </form>
        <script type="text/javascript">
            Duo.init({
                'host':"<%=API_HOSTNAME%>",
                'sig_request': "<%=SIG_REQUEST%>",
                'post_action': "/oam/server/auth_cred_submit"
            });
        </script>
    </body>
</html>
