package auyeung.stephen.main;

import auyeung.stephen.auth.service.AuthenticationResponse;
import auyeung.stephen.auth.service.AuthenticationService;
import auyeung.stephen.auth.service.CredentialDataProvider;
import auyeung.stephen.auth.service.RoleAlreadyExistsException;

public class Auth {

    public static void main(String[] args) {


        CredentialDataProvider prv = CredentialDataProvider.getInstance();

        AuthenticationService srv = new AuthenticationService(prv, true);

        var response = srv.CreateRole("ReadWrite");
        response = srv.CreateRole("ReadOnly");

        var roles = srv.getAllRoles();

        response = srv.DeleteRole("ReadOnly");


        response = srv.CreateUser("stephen", "plainPass");
        AuthenticationResponse ar = srv.authenticate("stephen", "plainPass");
        String token = ar.getToken();

        srv.addRoleToUser("stephen", "ReadWrite");
        var authResponse = srv.authenticateToken("stephen", token);

        srv.addRoleToUser("stephen", "ReadWrite");

        boolean aduthor = ar.getAuthorized();

        boolean t = srv.checkRole("ReadWrite");
        t = srv.checkRole("ReadOnly");

        var deleteres = srv.DeleteRole("ReadWrite");
        deleteres = srv.DeleteRole("ReadWrite");

        var d = srv.authenticateAsAnonymous();
        boolean author = d.getAuthorized();

        var anon = srv.authenticateAsAnonymous();
        anon.getAuthorized();
    }

}
