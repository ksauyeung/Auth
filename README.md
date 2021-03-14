The auyeung.stephen.auth.service.AuthenticationService is the primary service class implementing the IAuthenticationService interface
It uses ICredentialDataProvider as a backing data store for users and roles.

There are two ctors:

AuthenticationService(boolean allowAnonymousAccess)
  uses default a impelemtnation of ICredentialDataProvider, which provides in memory storage of all users and roles
 
AuthenticationService(ICredentialDataProvider credentialDataProvider, boolean allowAnonymousAccess)
  Provided for injection of ICredentialDataProvider

For some reason JUnit test cannot be loaded into this strange IDE, so most tests are not written.

Some demo code is writte in auyeung.stephen.main.Main class
