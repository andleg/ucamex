package uk.ac.cam.caret.oae.profile;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMap.Builder;

import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.servlets.post.ModificationType;
import org.sakaiproject.nakamura.api.lite.Session;
import org.sakaiproject.nakamura.api.lite.StorageClientUtils;
import org.sakaiproject.nakamura.api.lite.authorizable.AuthorizableManager;
import org.sakaiproject.nakamura.api.lite.authorizable.User;
import org.sakaiproject.nakamura.api.user.LiteAuthorizablePostProcessService;
import org.sakaiproject.nakamura.api.user.UserConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;

/**
 * This should be protected by a trusted proxy that will either set a header or set a
 * parameter on the request. That parameter will contain the user to be created. If the
 * servlet is protected and the header is set a POST will create the user and accept the
 * terms. If the userId from the session is not Anon, then the process will be requested
 * accepting terms for the user and assuming the user does not exist. Anon users are not
 * allowed (403), trying to create a user that already exists is a conflict (409), trying
 * to accept terms for a user that does not exist and not create is a not found 404.
 */
@SlingServlet(paths = { "/system/ucam/acceptterms", "/system/ucam/c/r/a",
    "/system/ucam/c/f/a" }, methods = "POST")
public class AcceptTermsServlet extends SlingAllMethodsServlet {

  /**
   * 
   */
  private static final long serialVersionUID = -8812325731250311990L;

  private static final Logger LOGGER = LoggerFactory.getLogger(AcceptTermsServlet.class);

  @Reference
  private transient LiteAuthorizablePostProcessService postProcessorService;

  @Reference
  private TrustedProxy trustedProxy;

  @Override
  protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response)
      throws ServletException, IOException {

    try {
      Session session = StorageClientUtils.adaptToSession(request.getResourceResolver()
          .adaptTo(javax.jcr.Session.class));
      String userId = trustedProxy.getUserIdFromProxy(request);
      boolean create = true;
      if (userId == null) {
        create = false;
        userId = session.getUserId();
        if (User.ADMIN_USER.equals(userId)) {
          userId = request.getParameter("uid");
        }
      }
      if (userId == null || User.ANON_USER.equals(userId)) {
        response.setStatus(403);
        return;
      }

      response.setStatus(acceptTerms(session, request, userId,
          request.getParameter("gn"), request.getParameter("sn"), create));
    } catch (Exception e) {
      LOGGER.error(e.getMessage(), e);
      throw new ServletException(e.getMessage(), e);
    }

  }

  private int acceptTerms(Session session, SlingHttpServletRequest request,
      String userId, String firstName, String lastName, boolean create) throws Exception {
    AuthorizableManager authorizableManager = session.getAuthorizableManager();
    if (create) {
      User user = (User) authorizableManager.findAuthorizable(userId);
      if (user != null) {
        return 409;
      }
      Builder<String, Object> b = ImmutableMap.builder();
      b.put("hasacceptedterms", true);
      b.put("whenacceptedterms", new Date().toString());
      b.put(UserConstants.USER_FIRSTNAME_PROPERTY, firstName);
      b.put(UserConstants.USER_LASTNAME_PROPERTY, lastName);
      authorizableManager.createUser(userId, userId, null, b.build());
      user = (User) authorizableManager.findAuthorizable(userId);
      // we may need to adjust the properties here to create the rest of the information.
      postProcessorService.process(user, session, ModificationType.CREATE, request);
      authorizableManager.updateAuthorizable(user);
    } else {
      User user = (User) authorizableManager.findAuthorizable(userId);
      if (user == null) {
        return 404;
      }
      user.setProperty("hasacceptedterms", true);
      user.setProperty("whenacceptedterms", new Date().toString());
      user.setProperty(UserConstants.USER_FIRSTNAME_PROPERTY, firstName);
      user.setProperty(UserConstants.USER_LASTNAME_PROPERTY, lastName);
      authorizableManager.updateAuthorizable(user);
    }
    return 200;
  }

}
