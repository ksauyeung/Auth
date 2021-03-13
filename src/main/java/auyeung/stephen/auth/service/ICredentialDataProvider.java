package auyeung.stephen.auth.service;

import java.util.Collection;

public interface ICredentialDataProvider {

	/**
	 * Returns all existing users
	 * @return
	 */
	Collection<User> getAllUsers();
	
	/**
	 * Returns all existing roles
	 * @return
	 */
	Collection<Role> getAllRoles();
	
	
	Role createRole(String roleName) throws RoleAlreadyExistsException;
	
	void deleteRole(String roleName) throws RoleNotFoundException;
	
	/**
	 * Check if role exists
	 * @param roleName
	 * @return
	 */
	boolean hasRole(String roleName);
	
	/**
	 * Creates a new user
	 * @param userName userName, case-insensitive
	 * @param password password in plain text
	 * @return the created user
	 * @throws UserAlreadyExistsException
	 */
	User createUser(String userName, String password, byte[] salt) throws UserAlreadyExistsException;
	
	/**
	 * Delete a user
	 * @param userName userName, case-insensitive
	 * @throws UserNotFoundException
	 */
	void deleteUser(String userName) throws UserNotFoundException;
	
	/**
	 * Adds a role to user
	 * @param userName userName, case-insensitive
	 * @param role the name of the role
	 * @throws UserNotFoundException 
	 * @throws RoleNotFoundException 
	 */
	void addRoleToUser(String userName, String role) throws UserNotFoundException, RoleNotFoundException;

	User getUser(String userName) throws UserNotFoundException;
	
}
