/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.microsoft.azure.spring.autoconfigure.aad;

import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

import javax.validation.constraints.NotEmpty;

@Validated
@ConfigurationProperties("azure.activedirectory")
public class AADAuthenticationProperties {
    private static final String DEFAULT_SERVICE_ENVIRONMENT = "global";

    /**
     * Azure service environment/region name, e.g., cn, global
     */
    private String environment;
    /**
     * Registered application ID in Azure AD.
     * Must be configured when OAuth2 authentication is done in front end
     */
    private String clientId;
    /**
     * API Access Key of the registered application.
     * Must be configured when OAuth2 authentication is done in front end
     */
    private String clientSecret;
    /**
     * Azure AD groups.
     */
    @NotEmpty
    private List<String> activeDirectoryGroups;

    private String tenantId;

    private boolean allowTelemetry = true;

    public boolean isAllowTelemetry() {
        return allowTelemetry;
    }

    public void setAllowTelemetry(boolean allowTelemetry) {
        this.allowTelemetry = allowTelemetry;
    }

    public String getEnvironment() {
        return StringUtils.isEmpty(environment) ? DEFAULT_SERVICE_ENVIRONMENT : environment;
    }

    public void setEnvironment(String environment) {
        this.environment = environment;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getActiveDirectoryGroups() {
        return activeDirectoryGroups;
    }

    public void setactiveDirectoryGroups(List<String> activeDirectoryGroups) {
        this.activeDirectoryGroups = activeDirectoryGroups;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }
}
