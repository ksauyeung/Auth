import auyeung.stephen.auth.service.AuthenticationService;
import auyeung.stephen.auth.service.CredentialDataProvider;
import org.junit.Assert;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class AuthenticaationServiceTest {


    static AuthenticationService authenticationService;
    static CredentialDataProvider credentialDataProvider;
    @BeforeAll
    public static void setup(){
        credentialDataProvider = CredentialDataProvider.getInstance();
        authenticationService = new AuthenticationService(credentialDataProvider, true);
    }

    @BeforeEach
    void setupThis(){
        credentialDataProvider.clear();
    }

    @Test
    void CreateRoleShouldAddRoleToDataSource() {
        authenticationService.CreateRole("TEST_ROLE");
        Assert.assertTrue(authenticationService.checkRole("TEST_ROLE"));
    }

    @Test
    void DeleteRoleShouldDeleteRoleFromDataSource() {
        authenticationService.DeleteRole("TEST_ROLE");
        Assert.assertFalse(authenticationService.checkRole("TEST_ROLE"));
    }

}
