package auyeung.stephen.auth.service;

public class UserRoleActionResponse {
	
	protected final boolean success;
	protected final String error;
	
	public boolean getSuccess() {
		return success;
	}
	
	public String getError() {
		return error;
	}
	
	protected UserRoleActionResponse(boolean success, String error) {
		this.success = success;
		this.error = error;
	}
	
	public static UserRoleActionResponse SuccessfulUserRoleActionResponse = new UserRoleActionResponse(true, "");
	
	public static UserRoleActionResponse createFailedUserRoleActionResponse(String error) {
		return new UserRoleActionResponse(false, error);
	}

}
