package com.oracle;

import java.util.Map;
import java.util.logging.Level;
import javax.security.auth.Subject;
import java.security.SecureRandom;

import org.json.JSONObject;
import com.squareup.okhttp.Response;
import oracle.security.am.plugin.ExecutionStatus;
import oracle.security.am.plugin.MonitoringData;
import oracle.security.am.plugin.PluginAttributeContextType;
import oracle.security.am.plugin.PluginConfig;
import oracle.security.am.plugin.PluginResponse;
import oracle.security.am.plugin.authn.AbstractAuthenticationPlugIn;
import oracle.security.am.plugin.authn.AuthenticationContext;
import oracle.security.am.plugin.authn.AuthenticationException;
import oracle.security.am.plugin.authn.CredentialParam;
import oracle.security.am.plugin.authn.PluginConstants;
import oracle.security.am.plugin.impl.CredentialMetaData;
import oracle.security.am.plugin.impl.UserAction;
import oracle.security.am.plugin.impl.UserActionContext;
import oracle.security.am.plugin.impl.UserActionMetaData;
import oracle.security.am.plugin.impl.UserContextData;
import oracle.security.am.engines.common.identity.provider.UserIdentityProvider;
import oracle.security.am.engines.common.identity.provider.UserInfo;
import oracle.security.am.engines.common.identity.provider.exceptions.IdentityProviderException;
import oracle.security.am.common.utilities.principal.OAMGUIDPrincipal;
import oracle.security.am.common.utilities.principal.OAMUserDNPrincipal;
import oracle.security.am.common.utilities.principal.OAMUserPrincipal;
import oracle.security.am.engines.common.identity.provider.UserIdentityProviderFactory;
import oracle.security.am.common.policy.runtime.RuntimeAuthnScheme;

import com.duosecurity.duoweb.DuoWeb;
import com.duosecurity.client.Http;


public final class DuoPlugin extends AbstractAuthenticationPlugIn {

    private static final String JAR_VERSION = "1.1.0";
    private static final String WAR_VERSION = "1.1.0";
    // This value is in snake_case because it has to match the string that Duo
    // uses when POSTing back to the URL.
    private static final String credentialName = "sig_response";
    private static final String IKEY_PARAM = "ikey";
    private static final String SKEY_PARAM = "skey";
    private static final String AKEY_PARAM = "akey";
    private static final String HOST_PARAM = "host";
    private static final String FAILMODE = "Fail mode";

    // number of tries to contact Duo
    private static final int MAX_TRIES = 3;
    // duration of time in seconds until a retry is requested to Duo
    private static final int MAX_TIMEOUT = 10;

    // Regex-syntax string, indicating the things to remove during sanitization of a string
    private static final String SANITIZING_PATTERN = "[^A-Za-z0-9_@.]";

    String ikey = null;
    String skey = null;
    String akey = null;
    String host = null;
    String username = null;
    String failmode = null;
    String loginPageURL;

    @Override
    public ExecutionStatus initialize(final PluginConfig config)
            throws IllegalArgumentException {

        super.initialize(config);

        LOGGER.log(Level.INFO, this.getClass().getName()
                   + " initializing Duo Plugin");
        try {
            this.ikey = (String) config.getParameter(IKEY_PARAM);
            this.skey = (String) config.getParameter(SKEY_PARAM);
            this.host = (String) config.getParameter(HOST_PARAM);
            this.failmode = config.getParameter(FAILMODE)
                                  .toString()
                                  .toLowerCase();
        } catch (Exception error) {
            LOGGER.log(Level.SEVERE,
                       "Null value not allowed for required parameter",
                       error);
            throw new IllegalArgumentException("Null value not allowed for "
                                               + "required parameter");
        }

        LOGGER.log(Level.INFO, "Fail mode is set to: " + sanitizeForLogging(this.failmode));

        return ExecutionStatus.SUCCESS;
    }

    @Override
    public ExecutionStatus process(final AuthenticationContext context)
            throws AuthenticationException {

        UserActionMetaData userAction = null;
        ExecutionStatus status = ExecutionStatus.FAILURE;
        this.username = getUserName(context);

        // attempts to get the sign_response value that is POSTed back to the
        // URL after attempting to auth
        CredentialParam param =
                context.getCredential().getParam(credentialName);

        // gets values needed to construct the loginPageURL
        RuntimeAuthnScheme authScheme = (RuntimeAuthnScheme)
                context.getObjectAttribute("authentication_scheme");
        Map<String, String> params = authScheme.getChallengeParameters();
        String contextType = (String) params.get("contextType");

        if (contextType.equalsIgnoreCase("customWar")) {
            String challengeURL = (String) params.get("challenge_url");
            String contextValue = (String) params.get("contextValue");
            loginPageURL = contextValue + challengeURL;
        }

        if (context.getStringAttribute(AKEY_PARAM) == null) {
            this.akey = generateAkey();
            context.setStringAttribute(AKEY_PARAM, this.akey);
        }

        if ((param == null) || (param.getValue() == null)
                || (param.getValue().toString().length() == 0)) {
            try {
                LOGGER.log(Level.INFO, "Performing pre-authentication for "
                        + sanitizeForLogging(this.username) + " through Duo's service.");
                // if the user is already authed or the fail mode is set to safe
                // and Duo is unreachable, then allow the user to sign in
                String authOrAllow = performPreAuth();
                if (authOrAllow.equals("allow")) {
                    this.updatePluginResponse(context);
                    return ExecutionStatus.SUCCESS;
                }

            // propagate any errors to the top
            } catch (Exception error) {
                LOGGER.log(Level.SEVERE, "An error occurred during the preauth "
                        + "process. ", error);
                throw new AuthenticationException(error);
            }

            status = ExecutionStatus.PAUSE;

            this.username = getUserName(context);
            this.akey = context.getStringAttribute(AKEY_PARAM);
            String sigRequest = DuoWeb.signRequest(this.ikey, this.skey,
                                                   this.akey, this.username);

            // when the user refreshes the iframe page, this method is called
            // again and would usually add sigRequest and host
            // responses again. This call to removeResponse removes all client
            // responses that we previously added.
            context.removeResponse(PluginAttributeContextType.CLIENT);

            // attach sigRequest and host to the context object so it
            // can be retrieved in the jsp page
            context.addResponse(new PluginResponse("sig_request",
                    sigRequest, PluginAttributeContextType.CLIENT));
            context.addResponse(new PluginResponse("host",
                    this.host, PluginAttributeContextType.CLIENT));

            UserContextData urlContext = new UserContextData(loginPageURL,
                    new CredentialMetaData("URL"));
            UserActionContext actionContext = new UserActionContext();
            actionContext.getContextData().add(urlContext);

            if (contextType.equalsIgnoreCase("customWar")) {
                userAction = UserActionMetaData.FORWARD;

            } else if (contextType.equalsIgnoreCase("external")) {
                userAction = UserActionMetaData.REDIRECT_POST;

            }

            UserAction action = new UserAction(actionContext, userAction);
            context.setAction(action);
            this.updatePluginResponse(context);

        } else {
            // this string looks like:
            // "$SIG_RESPONSE_VALUE,host=$API_HOSTNAME_VALUE"
            String sigResponse = param.getValue().toString().split(",")[0];
            String userThatAuthed = null;

            try {
                this.akey = context.getStringAttribute(AKEY_PARAM);
                userThatAuthed = DuoWeb.verifyResponse(this.ikey, this.skey,
                                                       this.akey, sigResponse);
            } catch (Exception error) {
                LOGGER.log(Level.SEVERE,
                           "An exception occurred while "
                           + sanitizeForLogging(this.username)
                           + " attempted Duo two-factor authentication.",
                           error);
            }

            if (userThatAuthed != null && userThatAuthed.equals(this.username)) {
                LOGGER.log(Level.INFO,
                            sanitizeForLogging(this.username)
                            + " successfully Duo two-factor authenticated.");
                status = ExecutionStatus.SUCCESS;
            } else {
                LOGGER.log(Level.INFO,
                            sanitizeForLogging(this.username)
                            + " was unable to successfully Duo"
                            + " two-factor authenticate.");
                status = ExecutionStatus.FAILURE;
                this.updatePluginResponse(context);
            }
        }

        return status;

    }

    private Response sendPreAuthRequest() throws Exception {
        Http request = new Http("POST", this.host, "/auth/v2/preauth",
                MAX_TIMEOUT);
        request.addParam("username", this.username);
        String userAgent = getUserAgent();
        request.addHeader("User-Agent", userAgent);
        request.signRequest(this.ikey, this.skey);
        return request.executeHttpRequest();
    }

    String performPreAuth() throws Exception {

        if (this.failmode.equals("secure")) {
            return "auth";
        } else if (!this.failmode.equals("safe")) {
            throw new IllegalArgumentException("Fail mode must be either "
                                               + "safe or secure");
        }

        // check if Duo authentication is even necessary by calling preauth
        for (int i = 0; ; ++i) {
            try {
                Response preAuthResponse = sendPreAuthRequest();
                int statusCode = preAuthResponse.code();
                if (statusCode / 100 == 5) {
                    LOGGER.log(Level.WARNING,
                               "Duo 500 error. Fail open for user: "
                               + sanitizeForLogging(this.username));
                    return "allow";
                }

                // parse response
                JSONObject json = new JSONObject(preAuthResponse.body().string());
                if (!json.getString("stat").equals("OK")) {
                    throw new Exception(
                            "Duo error code (" + json.getInt("code") + "): "
                            + json.getString("message"));
                }

                String result = json.getJSONObject("response").getString("result");
                if (result.equals("allow")) {
                    LOGGER.log(Level.INFO, "Duo 2FA bypass for user: "
                               + sanitizeForLogging(this.username));
                    return "allow";
                }
                break;

            } catch (java.io.IOException error) {
                if (i >= this.MAX_TRIES - 1) {
                    LOGGER.log(Level.WARNING,
                               "Duo server unreachable. Fail open for user: "
                               + sanitizeForLogging(this.username), error);
                    return "allow";
                }
            }
        }
        return "auth";
    }

    @Override
    public String getDescription() {
        return "Duo Security's Plugin to allow users to 2FA with Duo";
    }

    @Override
    public Map<String, MonitoringData> getMonitoringData() {
        // Plugins can log DMS data which will be picked by the Auth framework
        // and logged.
        return null;
    }

    @Override
    public boolean getMonitoringStatus() {
        // Indicates if logging DMS data is enabled for the plugins.
        return false;
    }

    @Override
    public void setMonitoringStatus(final boolean status) {

    }

    @Override
    public String getPluginName() {
        return "DuoPlugin";
    }


    @Override
    public int getRevision() {
        return 0;
    }

    private void updatePluginResponse(final AuthenticationContext context) {
        String retAttrs[] = (String[]) null;

        String userName = getUserName(context);
        UserIdentityProvider provider = null;
        UserInfo user = null;
        try {
            provider = getUserIdentityProvider();
            user = provider.locateUser(userName);
            retAttrs = provider.getReturnAttributes();

        } catch (Exception error) {
            LOGGER.log(Level.SEVERE,
                       "OAM error retrieving user profile from configured "
                       + "identity store during Duo two-factor", error);

        }

        String userIdentity = user.getUserId();
        String userDN = user.getDN();
        Subject subject = new Subject();
        subject.getPrincipals().add(new OAMUserPrincipal(userIdentity));
        subject.getPrincipals().add(new OAMUserDNPrincipal(userDN));

        if (user.getGUID() != null) {
            subject.getPrincipals().add(new OAMGUIDPrincipal(user.getGUID()));

        } else {
            subject.getPrincipals().add(new OAMGUIDPrincipal(userIdentity));

        }
        context.setSubject(subject);

        CredentialParam param = new CredentialParam();
        param.setName(PluginConstants.KEY_USERNAME_DN);
        param.setType("string");
        param.setValue(userDN);
        context.getCredential().addCredentialParam(
                PluginConstants.KEY_USERNAME_DN, param);

        PluginResponse rsp = new PluginResponse();
        rsp = new PluginResponse();
        rsp.setName(PluginConstants.KEY_AUTHENTICATED_USER_NAME);
        rsp.setType(PluginAttributeContextType.LITERAL);
        rsp.setValue(userIdentity);
        context.addResponse(rsp);

        rsp = new PluginResponse();
        rsp.setName(PluginConstants.KEY_RETURN_ATTRIBUTE);
        rsp.setType(PluginAttributeContextType.LITERAL);
        rsp.setValue(retAttrs);
        context.addResponse(rsp);

        rsp = new PluginResponse();
        rsp.setName("authn_policy_id");
        rsp.setType(PluginAttributeContextType.REQUEST);
        rsp.setValue(context.getAuthnScheme().getName());
        context.addResponse(rsp);

    }

    private String getUserName(final AuthenticationContext context) {
        String userName = null;

        CredentialParam param = context.getCredential().getParam(
                "KEY_USERNAME");

        if (param != null) {
            userName = (String) param.getValue();
        }

        if ((userName == null) || (userName.length() == 0)) {
            userName = context.getStringAttribute("KEY_USERNAME");
        }

        return userName;
    }

    private UserIdentityProvider getUserIdentityProvider()
            throws IdentityProviderException {
        UserIdentityProvider retVal = null;

        if (retVal == null) {
            retVal = UserIdentityProviderFactory.getProvider();
        }

        return retVal;
    }

    static String generateAkey() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        random.nextBytes(bytes);
        return bytesToHex(bytes);
    }

    private static String bytesToHex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; ++j) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    static String getUserAgent() {
        String userAgent = "duo_oam/jar " + JAR_VERSION +
                           "/war " + WAR_VERSION + " (";

        userAgent = addKeyValueToUserAgent(userAgent, "java.version") + "; ";
        userAgent = addKeyValueToUserAgent(userAgent, "os.name") + "; ";
        userAgent = addKeyValueToUserAgent(userAgent, "os.arch") + "; ";
        userAgent = addKeyValueToUserAgent(userAgent, "os.version");

        userAgent += ")";

        return userAgent;
    }

    private static String addKeyValueToUserAgent(String userAgent, String key) {
        return userAgent += (key + "=" + System.getProperty(key));
    }

    static String sanitizeForLogging(String stringToSanitize) {
      if (stringToSanitize == null) {
        return "";
      }

      return stringToSanitize.replaceAll(SANITIZING_PATTERN, "");        
    }
}
