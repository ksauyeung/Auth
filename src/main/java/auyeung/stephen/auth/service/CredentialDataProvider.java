package auyeung.stephen.auth.service;

import java.util.Collection;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

public class CredentialDataProvider implements ICredentialDataProvider {
	
	private HashMap<String, User> users = new HashMap<String, User>();
	private HashMap<String, Role> roles = new HashMap<String, Role>();	
	ReadWriteLock rwUsers = new ReentrantReadWriteLock();
	ReadWriteLock rwRoles = new ReentrantReadWriteLock();

	/**
	 * Deletes all roles all users
	 */
	public void clear() {
		Lock wUser = rwUsers.writeLock();
		Lock wRole = rwRoles.writeLock();
		wUser.lock();
		wRole.lock();
		try {
			users.clear();
			roles.clear();
		} finally {
			wUser.unlock();
			wRole.unlock();
		}
	}
	
	public User getUser(String userName) throws UserNotFoundException {
		User user = users.get(userName);
		if(user == null) {
			throw new UserNotFoundException();
		}
		return user;
	}
	
	@Override
	public Collection<User> getAllUsers() {
		Lock rlock = rwUsers.readLock();
		rlock.lock();
		try {
			return users.values().stream().collect(Collectors.toList());
		} finally {
			rlock.unlock();
		}
	}

	@Override
	public Collection<Role> getAllRoles() {
		Lock rlock = rwRoles.readLock();
		rlock.lock();
		try {
			return roles.values().stream().collect(Collectors.toList());
		} finally {
			rlock.unlock();
		}
	}
	
	@Override
	public boolean hasRole(String roleName) {
		Lock rlock = rwRoles.readLock();
		rlock.lock();
		try {
			return roles.containsKey(roleName);
		} finally {
			rlock.unlock();
		}
	}
	
	@Override
	public synchronized Role createRole(String roleName) throws RoleAlreadyExistsException {
		Lock wlock = rwRoles.writeLock();
		wlock.lock();
		try {
			Role role = roles.get(roleName); 
			if(role == null) {
				role = new Role(roleName);
				roles.put(roleName, role);
			}
			return role; 
		} finally {
			wlock.unlock();
		}				
	}
	

	@Override
	public synchronized void deleteRole(String roleName) throws RoleNotFoundException {
		
		//Exclusive lock on users list while deleting roles
		Lock wUsers= rwUsers.writeLock();
		wUsers.lock();
		try {
			
			Role role = roles.remove(roleName);
			if(role == null) {
				throw new RoleNotFoundException();
			}
			for(User user : users.values()) {
				user.removeRole(role);
			}
			
		} finally {
			wUsers.unlock();
		}
		
	}
	
	@Override
	public User createUser(String userName, String passwordHash, byte[] salt) throws UserAlreadyExistsException {
		Lock wlock = rwUsers.writeLock();
		wlock.lock();
		try {
			User user = users.get(userName);
			if(user != null) {
				throw new UserAlreadyExistsException();
			}
			user = new User(userName, passwordHash, salt);
			users.put(userName, user);			
			return user;
		} finally {
			wlock.unlock();
		}
	}

	@Override
	public void deleteUser(String userName) throws UserNotFoundException {
		Lock wlock = rwUsers.writeLock();
		wlock.lock();
		try {
			User user = users.get(userName);
			if(user == null) {
				throw new UserNotFoundException();
			}
			user.setValid(false);
			user.removeAllRoles();
			users.remove(userName);
		} finally {
			wlock.unlock();
		}
	}

	@Override
	public synchronized void addRoleToUser(String userName, String roleName) throws UserNotFoundException, RoleNotFoundException {
		Lock rUser = rwUsers.readLock();
		rUser.lock();
		try {
			User user = users.get(userName);
			if(user == null) {
				throw new UserNotFoundException();
			}
			Role role = roles.get(roleName);
			if(role == null) {
				throw new RoleNotFoundException();				
			}
			user.addRole(role);
			
		} finally {
			rUser.unlock();
		}
	}
	
	private static volatile CredentialDataProvider instance;
	private static Object lock = new Object();

	private CredentialDataProvider() {
	}
	
	public static CredentialDataProvider getInstance() {
		CredentialDataProvider store = instance;
		if (store == null) {
			synchronized (lock) {
				store = instance;
				if (store == null)
					instance = store = new CredentialDataProvider();
			}
		}
		return store;
	}
	
}
