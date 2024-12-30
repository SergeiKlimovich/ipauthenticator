package com.firebird.keycloak;

import com.firebird.keycloak.util.IpUtils;
import jakarta.ws.rs.core.*;
import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.models.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author Sergei Klimovich
 */
public class IpAddressAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(IpAddressAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String allowedIPAddress = context.getAuthenticatorConfig().getConfig()
            .get(IpAddressAuthenticatorFactory.ALLOWED_IP_ADDRESSES_CONFIG_NAME);
        logger.infof("###### ALLOWED_IPs: %s", allowedIPAddress);
        String allowedHeader = context.getAuthenticatorConfig().getConfig()
            .get(IpAddressAuthenticatorFactory.ALLOWED_HEADER_CONFIG_NAME);
        logger.infof("###### ALLOWED_HEADERS: %s", allowedHeader);
        String allowedUserAgent = context.getAuthenticatorConfig().getConfig()
            .get(IpAddressAuthenticatorFactory.ALLOWED_USER_AGENT_CONFIG_NAME);
        logger.infof("###### ALLOWED_USER_AGENT: %s", allowedUserAgent);
        if (allowedIPAddress == null || allowedIPAddress.isEmpty()) {
            logger.warn("###### Allowed IP Address configuration is missing.");
            context.attempted();
            return;
        }

        String clientIp = context.getConnection().getRemoteAddr();
        logger.infof("###### CLIENT_IP: %s", clientIp);
        boolean isIPAllowed = isIpAllowed(clientIp, allowedIPAddress);

        logHeaders(context);

        boolean isHeaderAllowed = isHeaderAllowed(context.getHttpRequest().getHttpHeaders(), allowedHeader);

        String clientUserAgent = context.getHttpRequest().getHttpHeaders().getHeaderString("User-Agent");
        logger.infof("###### CLIENT_USER_AGENT: %s", clientUserAgent);
        boolean isUserAgentAllowed = (clientUserAgent != null && clientUserAgent.equals(allowedUserAgent));

        if (isIPAllowed || isHeaderAllowed || isUserAgentAllowed) {
            if (isIPAllowed) {
                logger.infof("###### Authentication successful for IP: %s", clientIp);
            }
            if (isHeaderAllowed) {
                logger.infof("###### Authentication successful for Header: %s", allowedHeader);
            }
            if (isUserAgentAllowed) {
                logger.infof("###### Authentication successful for User-Agent: %s", clientUserAgent);
            }
            UserModel user = getSingleUser(context);
            logger.info("###### USER: " + (user != null ? user.getUsername() : "null"));
            if (user != null) {
                context.setUser(user);
                logger.info("###### Successfully transitioned to the resource directly.");
                context.success();
            } else {
                logger.warn("###### No user found.");
                context.attempted();
            }
        } else {
            context.attempted();
        }
    }

    private UserModel getSingleUser(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        return context.getSession().users().getUserByUsername(realm, "readonly");
    }

    private boolean isIpAllowed(String clientIp, String allowedIPs) {
        return IpUtils.isIpAllowed(clientIp, allowedIPs);
    }

    private boolean isHeaderAllowed(HttpHeaders headers, String allowedHeader) {
        MultivaluedMap<String, String> allHeaders = headers.getRequestHeaders();
        for (String headerName : allHeaders.keySet()) {
            logger.infof("###### HEADER_NAME: %s", headerName);
            List<String> headerValues = allHeaders.get(headerName);
            logger.infof("###### HEADER_VALUES: %s", headerValues.get(0));
            if (headerName.equalsIgnoreCase("X-Custom-Header") && headerValues.contains(allowedHeader)) {
                return true;
            }
        }
        return false;
    }

    private void logHeaders(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> allHeaders = context.getHttpRequest().getHttpHeaders().getRequestHeaders();
        String headerString = allHeaders.entrySet().stream()
            .map(entry -> entry.getKey() + ": " + String.join(", ", entry.getValue()))
            .collect(Collectors.joining("\n"));
        logger.infof("###### CLIENT_HEADERS:\n%s", headerString);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
