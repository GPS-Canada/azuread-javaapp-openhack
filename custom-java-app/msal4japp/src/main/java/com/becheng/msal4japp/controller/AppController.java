package com.becheng.msal4japp.controller;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.becheng.msal4japp.helper.AuthHelper;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.jwt.JWTParser;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import static com.becheng.msal4japp.helper.AuthHelper.getAuthSessionObject;

@Controller
public class AppController {
    
    @Autowired
    AuthHelper authHelper;
    
    @RequestMapping("/app")
    public ModelAndView securePage(HttpServletRequest httpRequest) throws ParseException {

        ModelAndView mav = new ModelAndView("app");
        setAccountInfo(mav, httpRequest);
        return mav;
    }

    @RequestMapping("/api")
    public ModelAndView callApi(HttpServletRequest httpRequest) throws Throwable {

        ModelAndView mav = new ModelAndView("app");
        setAccountInfo(mav, httpRequest);
        // retrieve the token from cache, if token expired, refresh token, aka 'silent login'
        IAuthenticationResult result =  authHelper.getAuthResultBySilentFlow(httpRequest);
        // call the api 
        String b2cApiCallRes = callApi(result.accessToken());
        // add the api response to the model
        mav.addObject("api_call_res", b2cApiCallRes);

        return mav;
    }

    private String callApi(String accessToken){
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + accessToken);

        HttpEntity<String> entity = new HttpEntity<>(null, headers);

        String result = restTemplate.exchange(authHelper.authConfig.getApi(), 
            HttpMethod.GET, entity, String.class).getBody();

        return new Date() + "<br>" + result;
    }

    //     URL url = new URL(authHelper.getMsGraphEndpointHost() + "v1.0/me");
    //     HttpURLConnection conn = (HttpURLConnection) url.openConnection();

    //     // Set the appropriate header fields in the request header.
    //     conn.setRequestProperty("Authorization", "Bearer " + accessToken);
    //     conn.setRequestProperty("Accept", "application/json");

    //     String response = HttpClientHelper.getResponseStringFromConn(conn);


    // @RequestMapping("/msal4jsample/graph/me")
    // public ModelAndView getUserFromGraph(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
    //         throws Throwable {

    //     IAuthenticationResult result;
    //     ModelAndView mav;
    //     try {
    //         result = authHelper.getAuthResultBySilentFlow(httpRequest, httpResponse);
    //     } catch (ExecutionException e) {
    //         if (e.getCause() instanceof MsalInteractionRequiredException) {

    //             // If silent call returns MsalInteractionRequired, then redirect to Authorization endpoint
    //             // so user can consent to new scopes
    //             String state = UUID.randomUUID().toString();
    //             String nonce = UUID.randomUUID().toString();

    //             SessionManagementHelper.storeStateAndNonceInSession(httpRequest.getSession(), state, nonce);
    //             String authorizationCodeUrl = authHelper.getAuthorizationCodeUrl(
    //                     httpRequest.getParameter("claims"),
    //                     "User.Read",
    //                     authHelper.getRedirectUriGraph(),
    //                     state,
    //                     nonce);

    //             return new ModelAndView("redirect:" + authorizationCodeUrl);
    //         } else {

    //             mav = new ModelAndView("error");
    //             mav.addObject("error", e);
    //             return mav;
    //         }
    //     }

    //     if (result == null) {
    //         mav = new ModelAndView("error");
    //         mav.addObject("error", new Exception("AuthenticationResult not found in session."));
    //     } else {
    //         mav = new ModelAndView("auth_page");
    //         setAccountInfo(mav, httpRequest);

    //         try {
    //             mav.addObject("userInfo", getUserInfoFromGraph(result.accessToken()));

    //             return mav;
    //         } catch (Exception e) {
    //             mav = new ModelAndView("error");
    //             mav.addObject("error", e);
    //         }
    //     }
    //     return mav;
    // }

    // private String getUserInfoFromGraph(String accessToken) throws Exception {
    //     // Microsoft Graph user endpoint
    //     URL url = new URL(authHelper.getMsGraphEndpointHost() + "v1.0/me");
    //     HttpURLConnection conn = (HttpURLConnection) url.openConnection();

    //     // Set the appropriate header fields in the request header.
    //     conn.setRequestProperty("Authorization", "Bearer " + accessToken);
    //     conn.setRequestProperty("Accept", "application/json");

    //     String response = HttpClientHelper.getResponseStringFromConn(conn);

    //     int responseCode = conn.getResponseCode();
    //     if(responseCode != HttpURLConnection.HTTP_OK) {
    //         throw new IOException(response);
    //     }

    //     JSONObject responseObject = HttpClientHelper.processResponse(responseCode, response);
    //     return responseObject.toString();
    // }

    private void setAccountInfo(ModelAndView model, HttpServletRequest httpRequest) throws ParseException {
        IAuthenticationResult auth = getAuthSessionObject(httpRequest);

        model.addObject("idTokenClaims", JWTParser.parse(auth.idToken()).getJWTClaimsSet().getClaims());
        model.addObject("account", getAuthSessionObject(httpRequest).account());
    }

}
