package com.becheng.msal4japp.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.security.auth.message.config.AuthConfig;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.becheng.msal4japp.configuration.AuthConfiguration;
import com.becheng.msal4japp.helper.AuthHelper;
import com.becheng.msal4japp.helper.SessionManagementHelper;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.MsalException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;


@Component
public class AuthFilter implements Filter {

    // list all the routes that should not be authenticated
    private List<String> excludedUrls = Arrays.asList("/", "/favicon.ico");

    @Autowired
    private AuthHelper authHelper;
  
    /**
     * 
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (request instanceof HttpServletRequest) {

            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;

            try {
                
                // retrieve info of the request
                String currentUri = httpRequest.getRequestURL().toString();
                String path = httpRequest.getServletPath();
                String queryStr = httpRequest.getQueryString();
                String fullUrl = currentUri + (StringUtils.isEmpty(queryStr) ? "" : "?" + queryStr); 

                // 1. skip this filter for the paths listed in the exclusion list
                if(excludedUrls.contains(path)){
                    
                    chain.doFilter(request, response);
                    return;
                }

                // 2. check if the request contains an auth or error code returned by AAD/B2C via redirecturl 
                if(containsAuthenticationCode(httpRequest)){
                    
                    System.out.println("...processing redirect");    
                    authHelper.processAuthenticationCodeRedirect(httpRequest, currentUri, fullUrl);
                    chain.doFilter(request, response);
                    return;
                } 

                // 3. if user is not authenticated prompt for signin
                if(!isAuthenticated(httpRequest)){
                    
                    System.out.println("...signin user");    
                    authHelper.sendAuthRedirect(
                            httpRequest,
                            httpResponse,
                            authHelper.authConfig.getApiScope(),
                            authHelper.authConfig.getRedirectUri());
                    return;
                }
                
                // 4. if token expired, do silent login 
                if(isAccessTokenExpired(httpRequest)){

                    System.out.println("...token expired, issuing silent login");
                    updateAuthDataUsingSilentFlow(httpRequest, httpResponse);    
                }
                 
            } catch (MsalException authException) {
                
                // something went wrong (like expiration or revocation of token)
                // we should invalidate AuthData stored in session and redirect to Authorization server
                SessionManagementHelper.removePrincipalFromSession(httpRequest);

                // redirect to the AAD/B2C for user signin
                authHelper.sendAuthRedirect(
                        httpRequest,
                        httpResponse,
                        authHelper.authConfig.getApiScope(),
                        authHelper.authConfig.getRedirectUri());

                return;

            } catch (Throwable throwable) {
            
                httpResponse.setStatus(500);
                System.out.println(throwable.getMessage());
                request.setAttribute("error", throwable.getMessage());
                request.getRequestDispatcher("/error").forward(request, response);
                return;            
            
            }
        }

        chain.doFilter(request, response);
        return;
    }

    /**
     * Returns true if the request is a redirect from AAD/B2C with auth code 
     * OR an error code, otherwise false.
     * @param httpRequest
     * @return
     */
    private boolean containsAuthenticationCode(HttpServletRequest httpRequest) {
        Map<String, String[]> httpParameters = httpRequest.getParameterMap();

        boolean isPostRequest = httpRequest.getMethod().equalsIgnoreCase("POST");
        boolean containsErrorData = httpParameters.containsKey("error");
        boolean containIdToken = httpParameters.containsKey("id_token");
        boolean containsCode = httpParameters.containsKey("code");

        return isPostRequest && containsErrorData || containsCode || containIdToken;
    }

    /**
     * Returns true if the access token has expired, otherwise false.
     * @param httpRequest
     * @return
     */
    private boolean isAccessTokenExpired(HttpServletRequest httpRequest) {
        IAuthenticationResult result =  SessionManagementHelper.getAuthSessionObject(httpRequest);
        return result.expiresOnDate().before(new Date());
    }

    /**
     * Returns true is user is authenticated, otherwise false.
     * @param request
     * @return
     */
    private boolean isAuthenticated(HttpServletRequest request) {
        return request.getSession().getAttribute(AuthHelper.PRINCIPAL_SESSION_NAME) != null;
    }

    /**
     * 
     * @param httpRequest
     * @param httpResponse
     * @throws Throwable
     */
    private void updateAuthDataUsingSilentFlow(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
        throws Throwable {
        IAuthenticationResult authResult = authHelper.getAuthResultBySilentFlow(httpRequest);
        SessionManagementHelper.setSessionPrincipal(httpRequest, authResult);
    }


}
