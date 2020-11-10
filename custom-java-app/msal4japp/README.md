# Run Instructions

1. Run via Spring-boot
2. To change between AAD and AADB2S auth servers, update the following:
   - application.properties
     ```
     auth-server-type=aad or auth-server-type=b2c
     ```
   - AuthConfiguration.java
     ```
     @ConfigurationProperties("aad")  or @ConfigurationProperties("b2c")
     ```   
3. Launch url= localhost:8081
