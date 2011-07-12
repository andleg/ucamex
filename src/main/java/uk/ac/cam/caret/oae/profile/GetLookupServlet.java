package uk.ac.cam.caret.oae.profile;

import com.google.common.collect.Maps;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;
import org.apache.sling.commons.json.JSONException;
import org.apache.sling.commons.json.io.JSONWriter;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.sakaiproject.nakamura.api.lite.Session;
import org.sakaiproject.nakamura.api.lite.StorageClientException;
import org.sakaiproject.nakamura.api.lite.StorageClientUtils;
import org.sakaiproject.nakamura.api.lite.accesscontrol.AccessDeniedException;
import org.sakaiproject.nakamura.api.lite.authorizable.Authorizable;
import org.sakaiproject.nakamura.api.lite.authorizable.AuthorizableManager;
import org.sakaiproject.nakamura.api.lite.authorizable.User;
import org.sakaiproject.nakamura.util.ExtendedJSONWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.cam.caret.oae.ldap.SimpleLdapConnectionManager;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

@SlingServlet(paths="/system/ucam/lookup", methods="GET")
public class GetLookupServlet extends SlingSafeMethodsServlet {

  
  /**
   * 
   */
  private static final long serialVersionUID = -8812325731250311990L;


  private static final Logger LOGGER = LoggerFactory.getLogger(GetLookupServlet.class);




  private static final String USER_DN_TEMPLATE_DEFAULT = "uid={0},ou=people,o=University of Cambridge,dc=cam,dc=ac,dc=uk";

  @Property(value=USER_DN_TEMPLATE_DEFAULT)
  private static final String USER_DN_TEMPLATE = "userdn-template";
  

  @Reference
  private SimpleLdapConnectionManager simpleLdapConnectionManager;


  private String userDNTemplate;


  @Activate
  public void activate(Map<String, Object> properties) {
   modify(properties);
  }
  
  @Modified
  public void modify(Map<String, Object> properties) {
    userDNTemplate = OsgiUtil.toString(properties.get(USER_DN_TEMPLATE), USER_DN_TEMPLATE_DEFAULT);
  }




  @Override
  protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
      throws ServletException, IOException {
    
    try {
      Session session = StorageClientUtils.adaptToSession(request.getResourceResolver().adaptTo(javax.jcr.Session.class));
      AuthorizableManager authorizableManager = session.getAuthorizableManager();
      
      String userId = session.getUserId();
      if ( User.ADMIN_USER.equals(userId)) {
        userId = request.getParameter("uid");
      }
      
      Authorizable user = authorizableManager.findAuthorizable(userId);
      if ( user == null ) {
        response.sendError(404,"User "+userId+" does not exist locally");
        return;
      }
      
      Map<String, Object> lookupRecord = getLookupRecord(session, userId);
      Map<String, Object> out = Maps.newHashMap();
      if ( lookupRecord == null ) {
        out.put("remote", false);
      } else {
        lookupRecord.remove("jpegPhoto");
        out.put("remote", lookupRecord);
      }
      out.put("local", user.getSafeProperties());
      response.setStatus(HttpServletResponse.SC_OK);
      response.setContentType("application/json");
      response.setCharacterEncoding("UTF-8");
      JSONWriter jsonWriter = new JSONWriter(response.getWriter());
      
      ExtendedJSONWriter.writeValueMap(jsonWriter, out);
    } catch ( Exception e) {
      LOGGER.error(e.getMessage(),e);
      throw new ServletException(e.getMessage(),e);
    }
    response.setStatus(200);
    
  }



  private Map<String, Object> getLookupRecord(Session session, String userId) throws LDAPException, JSONException, StorageClientException, AccessDeniedException {
    LDAPConnection ldapConnection = null;
    try {
      ldapConnection = simpleLdapConnectionManager.getConnection();
      String userDN = MessageFormat.format(userDNTemplate, userId);
      LDAPEntry ldapEntry = ldapConnection.read(userDN);
      LDAPAttributeSet ldapAttributes = ldapEntry.getAttributeSet();
      Map<String, Object> attributes = Maps.newHashMap();
      for ( @SuppressWarnings("unchecked")
      Iterator<LDAPAttribute> i = ldapAttributes.iterator(); i.hasNext(); ) {
        LDAPAttribute la = i.next();
        String[] values = la.getStringValueArray();
        if ( values != null ) {
          if ( values.length > 1 ) {
            attributes.put(la.getName(), values);
          } else if ( values.length == 1) {
            attributes.put(la.getName(), values[0]);
          }
        }
      }
      return attributes;
    } catch ( Exception e ) {
      LOGGER.warn(e.getMessage());
      LOGGER.debug(e.getMessage(),e);
      return null;
    } finally {
      if ( ldapConnection != null ) {
        simpleLdapConnectionManager.returnConnection(ldapConnection);
      }
    }

  }



  
  

}
