package uk.ac.cam.caret.oae.profile;

import org.apache.sling.api.SlingHttpServletRequest;

/**
 * Defines an upstream proxy server that can be used to extract user information.
 */
public interface TrustedProxy {

  String getUserIdFromProxy(SlingHttpServletRequest request);

}
