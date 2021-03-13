package auyeung.stephen.auth.service;

public class Role {

	private final String role;
	private volatile boolean isValid; 
	
	Role(String role) {
		this.role = role;
	}

	String getName() {
		return role;
	}
	
	boolean isValid() {
		return isValid;
		
	}
	
	void setIsValid(boolean isValid) {
		this.isValid = isValid;
	}
	
	public String toString() {
		return getName();
	}
	
}
