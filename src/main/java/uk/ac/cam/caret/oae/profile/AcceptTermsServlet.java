package uk.ac.cam.caret.oae.profile;

import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.sakaiproject.nakamura.api.lite.Session;
import org.sakaiproject.nakamura.api.lite.StorageClientException;
import org.sakaiproject.nakamura.api.lite.StorageClientUtils;
import org.sakaiproject.nakamura.api.lite.accesscontrol.AccessDeniedException;
import org.sakaiproject.nakamura.api.lite.authorizable.AuthorizableManager;
import org.sakaiproject.nakamura.api.lite.authorizable.User;
import org.sakaiproject.nakamura.api.user.UserConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;

@SlingServlet(paths="/system/ucam/acceptterms", methods="POST")
public class AcceptTermsServlet extends SlingAllMethodsServlet {

  
  /**
   * 
   */
  private static final long serialVersionUID = -8812325731250311990L;


  private static final Logger LOGGER = LoggerFactory.getLogger(AcceptTermsServlet.class);


  @Override
  protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response)
      throws ServletException, IOException {
    
    try {
      Session session = StorageClientUtils.adaptToSession(request.getResourceResolver().adaptTo(javax.jcr.Session.class));
      AuthorizableManager authorizableManager = session.getAuthorizableManager();
      String userId = session.getUserId();
      if ( User.ADMIN_USER.equals(userId)) {
        userId = request.getParameter("uid");
      }
      
      acceptTerms(authorizableManager, userId, request.getParameter("gn"), request.getParameter("sn"));
    } catch ( Exception e) {
      LOGGER.error(e.getMessage(),e);
      throw new ServletException(e.getMessage(),e);
    }
    response.setStatus(200);
    
  }






  private void acceptTerms(AuthorizableManager authorizableManager, String userId, String firstName, String lastName) throws AccessDeniedException, StorageClientException {
    User user = (User) authorizableManager.findAuthorizable(userId);
    user.setProperty("hasacceptedterms", true);
    user.setProperty("whenacceptedterms", new Date().toString());
    user.setProperty(UserConstants.USER_FIRSTNAME_PROPERTY, firstName);
    user.setProperty(UserConstants.USER_LASTNAME_PROPERTY, lastName);
    authorizableManager.updateAuthorizable(user);
  }
  
  

}
