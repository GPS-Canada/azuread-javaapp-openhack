package com.becheng.msal4japp.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
@ConfigurationProperties("b2c")
public class AuthConfiguration {
    
    @Value("${auth-server-type}")
    private String serverAuthType; 
    // applicable for both AAD & B2C
    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private String signUpSignInAuthority;
    
    private String api;
    private String apiScope;

    // applicable for only B2C
    private String editProfileAuthority;
    private String resetPasswordAuthority;

}
