package uk.ac.cam.caret.oae.profile;

import com.google.common.collect.ImmutableSet;

import org.apache.commons.lang.StringUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Service;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;

@Component(metatype=true, immediate=true)
@Service(value=TrustedProxy.class)
public class TrustedProxyImpl implements TrustedProxy {

  
  private static final Logger LOGGER = LoggerFactory.getLogger(TrustedProxyImpl.class);
  private static final String DEFAULT_TRUSTED_HEADER_NAME = "";
  private static final String DEFAULT_TRUSTED_PARAMETER_NAME = "";
  private static final String DEFAULT_TRUSTED_PROXIES = "localhost;127.0.0.1;0:0:0:0:0:0:0:1%0";
  
  /** A list of all the known safe hosts to trust as servers */
  @Property(value =DEFAULT_TRUSTED_PROXIES)
  public static final String PROP_TRUSTED_PROXIES = "safe-hostsaddress";
  
  @Property(value =DEFAULT_TRUSTED_PARAMETER_NAME)
  private static final String PROP_TRUSTED_PARAMETER_NAME = "trusted-parameter";
  
  @Property(value =DEFAULT_TRUSTED_HEADER_NAME)
  private static final String PROP_TRUSTED_HEADER_NAME = "trusted-header";
  private Set<String> trustedProxyAddress;
  private String trustedHeaderName;
  private String trustedParameterName;
  
  @Activate
  @Modified
  public void modified(Map<String, Object> properties) {
    trustedHeaderName = OsgiUtil.toString(properties.get(PROP_TRUSTED_HEADER_NAME), DEFAULT_TRUSTED_HEADER_NAME);
    trustedParameterName = OsgiUtil.toString(properties.get(PROP_TRUSTED_PARAMETER_NAME), DEFAULT_TRUSTED_PARAMETER_NAME);
    trustedProxyAddress = ImmutableSet.of(StringUtils.split(OsgiUtil.toString(properties.get(PROP_TRUSTED_PROXIES), DEFAULT_TRUSTED_PROXIES),";"));
  }

  
  public String getUserIdFromProxy(SlingHttpServletRequest request) {
    String proxyAddress = request.getRemoteAddr();
    String userId = null;
    if ( trustedProxyAddress.contains(proxyAddress)) {
      if (trustedHeaderName.length() > 0) {
        userId = request.getHeader(trustedHeaderName);
        if (userId != null) {
          LOGGER.debug(
              "Injecting Trusted Token from request: Header [{}] indicated user was [{}] ",
              0, userId);
        }
      }
      if (userId == null && trustedParameterName.length() > 0) {
        userId = request.getParameter(trustedParameterName);
        if (userId != null) {
          LOGGER.debug(
              "Injecting Trusted Token from request: Parameter [{}] indicated user was [{}] ",
              trustedParameterName, userId);
        }
      }
    }
    return userId;
  }

}
