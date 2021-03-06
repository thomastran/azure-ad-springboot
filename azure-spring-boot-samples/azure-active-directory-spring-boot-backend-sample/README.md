### How to configure

#### Register your application with your Azure Active Directory Tenant

Follow the guide [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code#register-your-application-with-your-ad-tenant).

#### Configure groups for sign in user

In order to try the authorization action with this sample with minimum effort, [configure the user and groups in Azure Active Directory](https://docs.microsoft.com/en-us/azure/active-directory/active-directory-groups-create-azure-portal), configure the user with `group1`. 


#### Configure application.properties

```properties
spring.security.oauth2.client.registration.azure.client-id=xxxxxx-your-client-id-xxxxxx
spring.security.oauth2.client.registration.azure.client-secret=xxxxxx-your-client-secret-xxxxxx

azure.activedirectory.tenant-id=xxxxxx-your-tenant-id-xxxxxx
# It's suggested the logged in user should at least belong to one of the below groups
# If not, the logged in user will not be able to access any authorization controller rest APIs
azure.activedirectory.active-directory-groups=group1, group2
```

### How to run

   - Use Maven 

     ```
     # Under azure-spring-boot project root directory
     mvn clean install -DskipTests
     cd azure-spring-boot-samples
     cd azure-active-directory-spring-boot-backend-sample
     mvn spring-boot:run
     ```

### Check the authentication and authorization
	
1. Access http://localhost:8080
2. Login
3. Access `group1 Message` link, should success
4. Access `group2 Message` link, should fail with forbidden error message


### Want to take full control over every configuration property

If you want to adjust the configuration properties according to certain requirements, try below application.properties and change accordingly.

```properties
spring.security.oauth2.client.registration.azure.client-id=xxxxxx-your-client-id-xxxxxx
spring.security.oauth2.client.registration.azure.client-secret=xxxxxx-your-client-secret-xxxxxx
spring.security.oauth2.client.registration.azure.client-name=Azure
spring.security.oauth2.client.registration.azure.provider=azure-oauth-provider
spring.security.oauth2.client.registration.azure.scope=openid, https://graph.microsoft.com/user.read
spring.security.oauth2.client.registration.azure.redirect-uri-template={baseUrl}/login/oauth2/code/{registrationId}
spring.security.oauth2.client.registration.azure.client-authentication-method=basic
spring.security.oauth2.client.registration.azure.authorization-grant-type=authorization_code

spring.security.oauth2.client.provider.azure-oauth-provider.authorization-uri=https://login.microsoftonline.com/common/oauth2/authorize
spring.security.oauth2.client.provider.azure-oauth-provider.token-uri=https://login.microsoftonline.com/common/oauth2/token
spring.security.oauth2.client.provider.azure-oauth-provider.user-info-uri=https://login.microsoftonline.com/common/openid/userinfo
spring.security.oauth2.client.provider.azure-oauth-provider.jwk-set-uri=https://login.microsoftonline.com/common/discovery/keys
spring.security.oauth2.client.provider.azure-oauth-provider.user-name-attribute=name

azure.activedirectory.tenant-id=xxxxxx-your-tenant-id-xxxxxx
azure.activedirectory.active-directory-groups=group1, group2
```
