package com.becheng.msal4japp.helper;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.naming.ServiceUnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.becheng.msal4japp.configuration.AuthConfiguration;
import com.becheng.msal4japp.pojo.StateData;
import com.microsoft.aad.msal4j.AuthorizationCodeParameters;
import com.microsoft.aad.msal4j.AuthorizationRequestUrlParameters;
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.IConfidentialClientApplication;
import com.microsoft.aad.msal4j.Prompt;
import com.microsoft.aad.msal4j.ResponseMode;
import com.microsoft.aad.msal4j.SilentParameters;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import static com.becheng.msal4japp.helper.SessionManagementHelper.FAILED_TO_VALIDATE_MESSAGE;

@Component
public class AuthHelper {
    
    public static final String PRINCIPAL_SESSION_NAME = "principal";
    public static final String TOKEN_CACHE_SESSION_ATTRIBUTE = "token_cache";

    @Autowired
    public AuthConfiguration authConfig;

    /**
     * Issues a http redirect to the auth server to request an authorization code
     * @param httpRequest
     * @param httpResponse
     * @param scope
     * @param redirectURL
     * @throws IOException
     */
    public void sendAuthRedirect(HttpServletRequest httpRequest, HttpServletResponse httpResponse, 
        String scope, String redirectURL) throws IOException {

        // state parameter to validate response from Authorization server 
        String state = UUID.randomUUID().toString();

        //  nonce parameter to validate idToken
        String nonce = UUID.randomUUID().toString();

        // store state and nonce in session
        SessionManagementHelper.storeStateAndNonceInSession(httpRequest.getSession(), state, nonce);

        // indicate a redirect status, 302 
        httpResponse.setStatus(302);

        // build the authcode url
        String authorizationCodeUrl = buildAuthorizationCodeUrl(
            httpRequest.getParameter("claims"), 
            scope, 
            redirectURL, 
            state, 
            nonce);
        
        // issue the redirect
        httpResponse.sendRedirect(authorizationCodeUrl);
    }

    /**
     * Redeems an auth code for an access_token and/or id_token with the auth server
     * @param httpRequest
     * @param currentUri
     * @param fullUrl
     * @throws Throwable
     */
    public void processAuthenticationCodeRedirect(HttpServletRequest httpRequest, String currentUri, String fullUrl)
        throws Throwable {

        // retrieve the parameters of the request to process
        Map<String, List<String>> params = extractRequestParams(httpRequest);

        // validate that state in response equals to state in request
        // state validation is used to prevent cross-site request attacks, i.e the request is not altered and is sent from the original server
        // state is used to validate the auth request
        StateData stateData = SessionManagementHelper.validateState(httpRequest.getSession(), params.get(SessionManagementHelper.STATE).get(0));

        // get the auth response to validate
        AuthenticationResponse authResponse = AuthenticationResponseParser.parse(new URI(fullUrl), params);
        
        // check if auth response was successful, i.e. instanceof IauthSuccessResp, cast it and validate it
        if (AuthHelper.isAuthenticationSuccessful(authResponse)) {
            
            AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;
            
            // validate that OIDC Auth Response matches Code Flow (contains only requested artifacts)
            validateAuthRespMatchesAuthCodeFlow(oidcResponse);

            // redeem the auth code for access and/or id tokens
            IAuthenticationResult result = getAuthResultByAuthCode(
                    httpRequest,
                    oidcResponse.getAuthorizationCode(),
                    currentUri,
                    Collections.singleton(authConfig.getApiScope()));

            // validate nonce to prevent reply attacks (code maybe substituted to one with broader access)
            // nonce - string value used to associate a Client session with an ID Token, and to mitigate replay attacks.
            // nonce is used to validate the token is valid
            validateNonce(stateData, getNonceClaimValueFromIdToken(result.idToken()));

            // store the result under a principal key to indicate user is authenticated.
            SessionManagementHelper.setSessionPrincipal(httpRequest, result);
 
        } else { //otherwise, cast it to an error response and throw an exception


            AuthenticationErrorResponse oidcResponse = (AuthenticationErrorResponse) authResponse;
            throw new Exception(String.format("Request for auth code failed: %s - %s",
                    oidcResponse.getErrorObject().getCode(),
                    oidcResponse.getErrorObject().getDescription()));
        }
    }

    /**
     * Returns the authentication result object from session.
     * @param request
     * @return
     */
    public static IAuthenticationResult getAuthSessionObject(HttpServletRequest request) {
        Object principalSession = request.getSession().getAttribute(PRINCIPAL_SESSION_NAME);
        if(principalSession instanceof IAuthenticationResult){
            return (IAuthenticationResult) principalSession;
        } else {
            throw new IllegalStateException();
        }
    }

    /**
     * Performs a silent login, aka returns the tokens from cache if not expired, otherwise aquires new tokens silent using the refresh token
     * @param httpRequest
     * @param httpResponse
     * @return
     * @throws Throwable
     */
    public IAuthenticationResult getAuthResultBySilentFlow(HttpServletRequest httpRequest)
        throws Throwable {

        IAuthenticationResult result =  SessionManagementHelper.getAuthSessionObject(httpRequest);

        IConfidentialClientApplication app = createClientApplication();

        Object tokenCache = httpRequest.getSession().getAttribute("token_cache");
        if (tokenCache != null) {
            app.tokenCache().deserialize(tokenCache.toString());
        }

        SilentParameters parameters = SilentParameters.builder(
                Collections.singleton(authConfig.getApiScope()),
                result.account()).build();

        CompletableFuture<IAuthenticationResult> future = app.acquireTokenSilently(parameters);
        IAuthenticationResult updatedResult = future.get();

        //update session with latest token cache
        SessionManagementHelper.storeTokenCacheInSession(httpRequest, app.tokenCache().serialize());

        return updatedResult;
    }

    private String buildAuthorizationCodeUrl(String claims, String scope, String registeredRedirectURL, String state, String nonce)
        throws MalformedURLException {

        String updatedScopes = scope == null ? "" : scope;

        ConfidentialClientApplication authapp = createClientApplication();

        AuthorizationRequestUrlParameters parameters =
            AuthorizationRequestUrlParameters
                .builder(registeredRedirectURL,
                        Collections.singleton(updatedScopes))
                .responseMode(ResponseMode.QUERY)
                .prompt(Prompt.SELECT_ACCOUNT)
                .state(state)
                .nonce(nonce)
                .claimsChallenge(claims)
                .build();

        return authapp.getAuthorizationRequestUrl(parameters).toString();
    }

    // redeem the auth code from the auth server for an access_token and/or id_token   
    private IAuthenticationResult getAuthResultByAuthCode(
            HttpServletRequest httpServletRequest,
            AuthorizationCode authorizationCode,
            String currentUri, Set<String> scopes) throws Throwable {

        IAuthenticationResult result;
        ConfidentialClientApplication app;
        try {
            app = createClientApplication();

            String authCode = authorizationCode.getValue();
            AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
                    authCode,
                    new URI(currentUri))
                    .scopes(scopes)
                    .build();

            // async call                     
            Future<IAuthenticationResult> future = app.acquireToken(parameters);

            result = future.get();

        } catch (ExecutionException e) {
            throw e.getCause();
        }

        if (result == null) {
            throw new ServiceUnavailableException("authentication result was null");
        }

        // store the token cache in session
        SessionManagementHelper.storeTokenCacheInSession(httpServletRequest, app.tokenCache().serialize());

        return result;
    }

    private Map extractRequestParams(HttpServletRequest httpRequest){
        Map<String, List<String>> params = new HashMap<>();
        for (String key : httpRequest.getParameterMap().keySet()) {
            params.put(key, Collections.singletonList(httpRequest.getParameterMap().get(key)[0]));
        }
        return params;
    }

    private static boolean isAuthenticationSuccessful(AuthenticationResponse authResponse) {
        return authResponse instanceof AuthenticationSuccessResponse;
    }

    // only the auth code should be returned
    private void validateAuthRespMatchesAuthCodeFlow(AuthenticationSuccessResponse oidcResponse) throws Exception {
        if (oidcResponse.getIDToken() != null || oidcResponse.getAccessToken() != null ||
                oidcResponse.getAuthorizationCode() == null) {
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "unexpected set of artifacts received");
        }
    }

    // build and return confidential client app, i.e. for webapps where secrets can be stored safely
    // if using a SPA, mobile app, then build and return a public client app instead 
    private ConfidentialClientApplication createClientApplication() throws MalformedURLException {
        String authServerType = authConfig.getServerAuthType();
        
        ConfidentialClientApplication authapp;
        if ("aad".equals(authServerType)) {
            authapp = ConfidentialClientApplication.builder(authConfig.getClientId(), ClientCredentialFactory.createFromSecret(authConfig.getClientSecret()))
                .authority(authConfig.getSignUpSignInAuthority())
                .build();
        } else {
            authapp = ConfidentialClientApplication.builder(authConfig.getClientId(), ClientCredentialFactory.createFromSecret(authConfig.getClientSecret()))
                .b2cAuthority(authConfig.getSignUpSignInAuthority())
                .build();
        }
        return authapp;
    }           
                
    private void validateNonce(StateData stateData, String nonce) throws Exception {
        if (StringUtils.isEmpty(nonce) || !nonce.equals(stateData.getNonce())) {
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "could not validate nonce");
        }
    }

    private String getNonceClaimValueFromIdToken(String idToken) throws ParseException {
        return (String) JWTParser.parse(idToken).getJWTClaimsSet().getClaim("nonce");
    }

}
