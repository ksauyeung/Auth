package auyeung.stephen.auth.service;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

public class AuthenticationService implements IAuthenticationService {
	
	public static final int TOKEN_DURATION_MINUTES = 120;
	private static final String SPECIAL_ANON_TOKEN = "ABC123";
	private static final String SECRET = "ABCDEFGHIJKLMNOP";
	private final ICredentialDataProvider store;		
	private final Map<String, User> authenticatedUsers = new HashMap<String, User>();
	private final ReadWriteLock rwAuthenticatedUsers = new ReentrantReadWriteLock();
	
	private User anonymousUser = null;
	
	/**
	 * Create an Authentication Service using the default data store
	 */
	public AuthenticationService(boolean allowAnonymousAccess) {
		store = CredentialDataProvider.getInstance();
		if(allowAnonymousAccess) {
			initializeAnonymous();
		}
	}
	
	/**
	 * Create an Authentication Service using the custom data store
	 * @param credentialDataStore the data store
	 */
	public AuthenticationService(ICredentialDataProvider credentialDataProvider, boolean allowAnonymousAccess) {
		store = credentialDataProvider;
		if(allowAnonymousAccess) {
			initializeAnonymous();
		}
	}
	
	private void initializeAnonymous() {
		anonymousUser = new User("Guest", null, null);
		anonymousUser.setValid(true);
		anonymousUser.setToken(SPECIAL_ANON_TOKEN);
		anonymousUser.setTokeNExpiry(Long.MAX_VALUE);
		authenticatedUsers.put(anonymousUser.getToken(), anonymousUser);
	}
	
	public AuthenticationResponse authenticate(String userName, String password) {
		userName = Helper.normalizeUserName(userName);
		if(userName.length() == 0) {
			return AuthenticationResponse.FailedAuthenticationResponse("Authentication failed.");
		}
		if(password == null) {
			password = "";
		}
				
		try {
			User user = store.getUser(userName);
			synchronized(user) {
				String hashedPassword = Helper.hash(password, user.salt);
				if(user.getPasswordHash().equals(hashedPassword)) {
					generateToken(user);
					addUserToAuth(user);
					return new AuthenticationResponse(user);
				}
			}
			
		} catch (Exception e) {
			return AuthenticationResponse.FailedAuthenticationResponse("Authentication failed.");
		} finally {
			
		}
		return AuthenticationResponse.FailedAuthenticationResponse("Authentication failed.");
	}
	
	private void generateToken(User user) throws Exception {
		long expiry = System.currentTimeMillis() + TOKEN_DURATION_MINUTES * 60 * 1000;
		String msg = user.getUserName() + "|" + Long.toString(expiry);
		user.setToken(Helper.AESEncrypt(msg, SECRET));
		user.setTokeNExpiry(expiry);
		user.setValid(true);		
	}
	

	public AuthenticationResponse authenticateToken(String caller, String token) {
		caller = Helper.normalizeUserName(caller);
		User user = getUserFromAuth(token);
		if(user == null) {
			return AuthenticationResponse.FailedAuthenticationResponse("Token is not authorized.");
		}
		
		synchronized(user) {
			if(user.getTokenExpiry() + TOKEN_DURATION_MINUTES * 60 * 1000 < System.currentTimeMillis()) {
				removeUserFromAuth(user);
				return AuthenticationResponse.FailedAuthenticationResponse("Token has expired.");				
			}	
			
			try {
				String msg = Helper.AESDecrypt(token, SECRET);
				String t[] = msg.split("\\|");
				if(user.getUserName().equals(t[0]) && Long.parseLong(t[1]) == user.getTokenExpiry()) {
					return new AuthenticationResponse(user);
				}			
				
			} catch (Exception e) {
				return AuthenticationResponse.FailedAuthenticationResponse("Token is not authorized.");
			}
			
			return AuthenticationResponse.FailedAuthenticationResponse("Token has expired.");
		}

	}

	@Override
	public AuthenticationResponse authenticateAsAnonymous() {
		if(anonymousUser == null) {
			return AuthenticationResponse.FailedAuthenticationResponse("Guest access not allowed");
		} else {
			AuthenticationResponse response = new AuthenticationResponse(anonymousUser);
			return response;			
		}
	}

	@Override
	public void InvalidateToken(String token) {
		Lock wLock = rwAuthenticatedUsers.writeLock();
		wLock.lock();
		try {
			User user = authenticatedUsers.remove(token);
			if(user == null) {
				return;
			}				
			synchronized(user) {
				user.setValid(false);
				user.token = "";
				user.tokenExpiry = 0;
			}			
			
		} finally {
			wLock.unlock();
		}
	}
	
	@Override
	public UserRoleActionResponse CreateUser(String userName, String password) {
		userName = Helper.normalizeUserName(userName);
		if(userName.length() == 0) {
			return UserRoleActionResponse.createFailedUserRoleActionResponse("Username and must not be empty");
		}
		if(password == null) {
			password = "";
		}		
		
		try {
			byte[] salt = Helper.getNewSalt();
			String hashed = Helper.hash(password, salt);			
			store.createUser(userName, hashed, salt);
			
			return UserRoleActionResponse.SuccessfulUserRoleActionResponse;
					
		} catch (UserAlreadyExistsException e) {
			return UserRoleActionResponse.createFailedUserRoleActionResponse("User already exist");
			
		} catch (NoSuchAlgorithmException a) {
			return UserRoleActionResponse.createFailedUserRoleActionResponse("Technical error - NoSuchAlgorithmException");
		}
	}

	@Override
	public UserRoleActionResponse DeleteUser(String userName) {
		userName = Helper.normalizeUserName(userName);
		if(userName.length() == 0) {
			return UserRoleActionResponse.createFailedUserRoleActionResponse("Username and must not be empty");
		}
	
		try {
			store.deleteUser(userName);
			return UserRoleActionResponse.SuccessfulUserRoleActionResponse;
			
		} catch (UserNotFoundException e) {
			return UserRoleActionResponse.createFailedUserRoleActionResponse("User not found");
		}
	}
	
	public void addRoleToUser(String userName, String role) {
		try {
			store.addRoleToUser(userName, role);
		} catch (UserNotFoundException | RoleNotFoundException e) {
			// do nothing
		}
	}

	@Override
	public boolean checkRole(String roleName) {
		return store.hasRole(roleName);
	}

	@Override
	public Collection<String> getAllRoles() {
		return store.getAllRoles().stream().map(x->x.getName()).collect(Collectors.toList());
	}

	@Override
	public UserRoleActionResponse CreateRole(String roleName) {
		try {
			store.createRole(roleName);
			return UserRoleActionResponse.SuccessfulUserRoleActionResponse;
		} catch (RoleAlreadyExistsException e) {
			return UserRoleActionResponse.createFailedUserRoleActionResponse("Role already exists");
		}
	}

	@Override
	public UserRoleActionResponse DeleteRole(String roleName) {
		try {
			store.deleteRole(roleName);
			return UserRoleActionResponse.SuccessfulUserRoleActionResponse;
		} catch (RoleNotFoundException e) {
			return UserRoleActionResponse.createFailedUserRoleActionResponse("Role not found");
		}
	}
	
	
	
	
	private void addUserToAuth(User user) {
		Lock wLock = rwAuthenticatedUsers.writeLock();
		wLock.lock();
		try {
			authenticatedUsers.put(user.token, user);
		} finally {
			wLock.unlock();
		}
		
	}
	
	private void removeUserFromAuth(User user) {
		Lock wLock = rwAuthenticatedUsers.writeLock();
		wLock.lock();
		try {
			authenticatedUsers.remove(user.token);			
		} finally {
			wLock.unlock();
		}
	}
	
	private User getUserFromAuth(String token) {
		Lock rLock = rwAuthenticatedUsers.readLock();
		rLock.lock();
		try {
			return authenticatedUsers.get(token);			
		} finally {
			rLock.unlock();
		}
	}
	


}
