# Identity MVP(Java) Hack
A Hack to develop MVPs using Java to leverage Azure AD and Azure AD B2C identities. 

## Goals
1. MVP of user sign-in using Azure AD using Partner's code base.
2. MVP of user sign-in using Azure AD B2C using Partner's code base. 

## Agenda
| Day 1 | Day2 | Day 3 | Day 4 | Day 5 |
| --- | --- | --- | --- | --- | 
| **1pm - 1:30pm**: Kickoff and Team Intros <br> **1:30pm - 3pm**: Presentation + Demo (Ben) <br> **3pm - 4:pm**: Environment Overview and Setup (Partner) | **1pm - 2pm**: Demo of MS Identity Java Webapp Sample (AAD + B2C) <br> **2pm - 4pm**: Hack | **1pm - 4pm**: Hack  | **1pm - 3pm**: Hack <br> **3pm - 4pm**: Placeholder Identity PG Session | **1pm - 3pm**: Hack <br> **3pm - 4pm**: Closing & Lessons Learned

## Resources
- MSAL Java Library: https://github.com/AzureAD/microsoft-authentication-library-for-java
- Microsoft Identity Java Webapp Sample: https://github.com/Azure-Samples/ms-identity-java-webapp
- VSCode IDE: https://code.visualstudio.com/
- VSCode Java Extension Pack: https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-pack
- VSCode Spring Book Extension Pack: https://marketplace.visualstudio.com/items?itemName=Pivotal.vscode-boot-dev-pack


## Code Snippets
**[TODO]**
Sample:
```
String getAuthorizationCodeUrl(String claims, String scope, String registeredRedirectURL, String state, String nonce)
        throws MalformedURLException {

    String updatedScopes = scope == null ? "" : scope;

    PublicClientApplication pca = PublicClientApplication.builder(clientId).authority(authority).build();

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

    return pca.getAuthorizationRequestUrl(parameters).toString();
}
```
