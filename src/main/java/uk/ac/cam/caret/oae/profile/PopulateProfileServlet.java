package uk.ac.cam.caret.oae.profile;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.commons.json.JSONException;
import org.apache.sling.commons.json.JSONObject;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.sakaiproject.nakamura.api.lite.Session;
import org.sakaiproject.nakamura.api.lite.StorageClientException;
import org.sakaiproject.nakamura.api.lite.StorageClientUtils;
import org.sakaiproject.nakamura.api.lite.accesscontrol.AccessDeniedException;
import org.sakaiproject.nakamura.api.lite.authorizable.AuthorizableManager;
import org.sakaiproject.nakamura.api.lite.authorizable.User;
import org.sakaiproject.nakamura.api.profile.ProfileService;
import org.sakaiproject.nakamura.api.templates.TemplateService;
import org.sakaiproject.nakamura.util.LitePersonalUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.ac.cam.caret.oae.ldap.SimpleLdapConnectionManager;

import java.io.IOException;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.ServletException;

@SlingServlet(paths="/system/ucam/profile-setup", methods="POST")
public class PopulateProfileServlet extends SlingAllMethodsServlet {

  
  /**
   * 
   */
  private static final long serialVersionUID = -8812325731250311990L;


  private static final Logger LOGGER = LoggerFactory.getLogger(PopulateProfileServlet.class);


  private static final String PROFILE_IMPORT_TEMPLATE_DEFAULT = "{  \"testing\": true }";

  @Property(value=PROFILE_IMPORT_TEMPLATE_DEFAULT)
  private static final String PROFILE_IMPORT_TEMPLATE = "import-template";

  private static final String USER_DN_TEMPLATE_DEFAULT = "{userId}";

  @Property(value=USER_DN_TEMPLATE_DEFAULT)
  private static final String USER_DN_TEMPLATE = "userdn-template";


  
  
  @Reference
  private ProfileService profileService;
  
  @Reference
  private TemplateService templateService;


  @Reference
  private SimpleLdapConnectionManager simpleLdapConnectionManager;


  private String importTemplate;


  private String userDNTemplate;


  @Activate
  public void activate(Map<String, Object> properties) {
    importTemplate = OsgiUtil.toString(properties.get(PROFILE_IMPORT_TEMPLATE), PROFILE_IMPORT_TEMPLATE_DEFAULT);
    userDNTemplate = OsgiUtil.toString(properties.get(USER_DN_TEMPLATE), USER_DN_TEMPLATE_DEFAULT);
  }


  @Override
  protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response)
      throws ServletException, IOException {
    
    try {
      Session session = StorageClientUtils.adaptToSession(request.adaptTo(ResourceResolver.class).adaptTo(javax.jcr.Session.class));
      AuthorizableManager authorizableManager = session.getAuthorizableManager();
      String userId = session.getUserId();
      
      syncProfile(session, userId);
      
      
      acceptTerms(authorizableManager, userId);
    } catch ( Exception e) {
      LOGGER.error(e.getMessage(),e);
      throw new ServletException(e.getMessage(),e);
    }
    response.setStatus(200);
    
  }



  private void syncProfile(Session session, String userId) throws LDAPException, JSONException, StorageClientException, AccessDeniedException {
    LDAPConnection ldapConnection = null;
    try {
      ldapConnection = simpleLdapConnectionManager.getConnection();
      String userDN = templateService.evaluateTemplate(ImmutableMap.of("uid", userId), userDNTemplate);
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
      
      JSONObject importJson = new JSONObject(templateService.evaluateTemplate(attributes, importTemplate));
      profileService.update(session, LitePersonalUtils.getProfilePath(userId), importJson);
    } finally {
      if ( ldapConnection != null ) {
        simpleLdapConnectionManager.returnConnection(ldapConnection);
      }
    }

  }



  private void acceptTerms(AuthorizableManager authorizableManager, String userId) throws AccessDeniedException, StorageClientException {
    User user = (User) authorizableManager.findAuthorizable(userId);
    user.setProperty("hasacceptedterms", true);
    user.setProperty("whenacceptedterms", new Date().toString());
    authorizableManager.updateAuthorizable(user);
  }
  
  

}
