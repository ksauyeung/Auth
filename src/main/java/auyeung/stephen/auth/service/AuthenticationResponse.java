package auyeung.stephen.auth.service;

import java.util.Collection;

public class AuthenticationResponse {
	
	private boolean authorized;
	private Collection<Role> roles;
	private String token;
	private long tokenExpiry;
	private String error;
	
	public Collection<Role> getRoles() {
		return roles;
	}

	public String getError() {
		return error;
	}

	public boolean getAuthorized() {
		return authorized;
	}

	public String getToken() {
		return token;
	}


	public long getTokenExpiry() {
		return tokenExpiry;
	}

	private AuthenticationResponse() {
		
	}

	AuthenticationResponse(User user) {
		this.authorized = true;
		this.roles = user.getAllRoles();
		this.token = user.getToken();
		this.tokenExpiry = user.getTokenExpiry();
		this.error = "";
	}

	public static AuthenticationResponse FailedAuthenticationResponse(String error) {
		AuthenticationResponse response = new AuthenticationResponse();
		response.authorized = false;
		response.roles = null;
		response.token = null;
		response.tokenExpiry = -1;
		response.error = error;
		return response;		
	}
}
