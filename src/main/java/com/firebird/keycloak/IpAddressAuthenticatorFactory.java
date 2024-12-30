package com.firebird.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.*;

/**
 * @author Sergei Klimovich
 */
public class IpAddressAuthenticatorFactory implements AuthenticatorFactory {

    private static final String PROVIDER_ID = "ip-header-user-agent-authenticator";
    private static final IpAddressAuthenticator SINGLETON = new IpAddressAuthenticator();
    static final String ALLOWED_IP_ADDRESSES_CONFIG_NAME = "allowed_ip_addresses";
    static final String ALLOWED_HEADER_CONFIG_NAME = "allowed_header";
    static final String ALLOWED_USER_AGENT_CONFIG_NAME = "allowed_user_agent";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "IP, HEADER, USER_AGENT Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return List.of(AuthenticationExecutionModel.Requirement.REQUIRED)
            .toArray(new AuthenticationExecutionModel.Requirement[0]);
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Executes the flow only if the client IP, HEADER or USER_AGENT match any of the configured datas.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty ipProperty = new ProviderConfigProperty();
        ipProperty.setType(ProviderConfigProperty.STRING_TYPE);
        ipProperty.setName(ALLOWED_IP_ADDRESSES_CONFIG_NAME);
        ipProperty.setLabel("Allowed IPs to skip Authorization. Supports IPv4 and IPv6 addresses in CIDR or single format");
        ipProperty.setHelpText("Supports multiple IPs separated by commas.");

        ProviderConfigProperty headerProperty = new ProviderConfigProperty();
        headerProperty.setType(ProviderConfigProperty.STRING_TYPE);
        headerProperty.setName(ALLOWED_HEADER_CONFIG_NAME);
        headerProperty.setLabel("Allowed value of X-Custom-Header to skip Authorization");
        headerProperty.setHelpText("Supports only one header.");

        ProviderConfigProperty userAgentProperty = new ProviderConfigProperty();
        userAgentProperty.setType(ProviderConfigProperty.STRING_TYPE);
        userAgentProperty.setName(ALLOWED_USER_AGENT_CONFIG_NAME);
        userAgentProperty.setLabel("Allowed User Agent to skip Authorization");
        userAgentProperty.setHelpText("Supports only one user agent.");

        configProperties.add(ipProperty);
        configProperties.add(headerProperty);
        configProperties.add(userAgentProperty);

        return configProperties;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }
}
