package auyeung.stephen.auth.service;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

class User {

	protected final Collection<Role> roles = new HashSet<Role>(0);
	protected final String userName;
	protected byte[] salt;
	protected String passwordHash;
	protected String token;
	protected long tokenExpiry;
	protected volatile boolean isValid;
	private ReadWriteLock rwRoles = new ReentrantReadWriteLock();	
	
	User(String userName, String passwordHash, byte[] salt) {
		this.userName = userName;
		this.passwordHash = passwordHash;
		this.salt = salt;
	}
	
	String getUserName() {
		return userName;
	}
	
	String getToken() {
		return token;
	}
	
	void setToken(String token) {
		this.token = token;
	}
	
	long getTokenExpiry() {
		return tokenExpiry;
	}

	void setTokeNExpiry(long expiry)  {
		this.tokenExpiry = expiry;
	}
	
	@Override
	public String toString() {
		return getUserName();
	}
	
	void removeAllRoles() {
		Lock wlock = rwRoles.writeLock();
		wlock.lock();
		try {
			roles.clear();
		} finally {
			wlock.unlock();
		}		
	}

	void removeRole(Role role) {
		Lock wlock = rwRoles.writeLock();
		wlock.lock();
		try {
			roles.remove(role);
		} finally {
			wlock.unlock();
		}		
	}
	
	void addRole(Role role) {
		Lock wlock = rwRoles.writeLock();
		wlock.lock();
		try {
			roles.add(role);
		} finally {
			wlock.unlock();
		}		
	}
	
	Collection<Role> getAllRoles() {
		Lock rlock = rwRoles.readLock();
		rlock.lock();
		try {
			return Collections.unmodifiableCollection(roles);
		} finally {
			rlock.unlock();
		}		
	}
	
	boolean getIsValid() {
		return isValid;
	}
	
	void setValid(boolean valid) {
		isValid = valid;
	}

	byte[] getSalt() {
		return salt;
	}

	String getPasswordHash() {
		return passwordHash;
	}
	
	
}
