package auyeung.stephen.auth.service;

import java.util.Collection;

public interface IAuthenticationService {
	
	AuthenticationResponse authenticate(String userName, String password);
	
	AuthenticationResponse authenticateToken(String caller, String token);
	
	AuthenticationResponse authenticateAsAnonymous();

	boolean checkRole(String roleName);
	
	Collection<String> getAllRoles();
	
	UserRoleActionResponse CreateUser(String userName, String password);
	
	UserRoleActionResponse DeleteUser(String userName);
	
	UserRoleActionResponse CreateRole(String roleName);
	
	UserRoleActionResponse DeleteRole(String roleName);

	void InvalidateToken(String token);
	
}
