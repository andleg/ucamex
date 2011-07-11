package uk.ac.cam.caret.oae.ldap;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;

public interface SimpleLdapConnectionManager {

  LDAPConnection getConnection() throws LDAPException;

  void returnConnection(LDAPConnection conn);

}
