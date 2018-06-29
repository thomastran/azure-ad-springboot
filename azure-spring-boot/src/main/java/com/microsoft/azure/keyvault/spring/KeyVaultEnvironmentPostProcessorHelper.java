/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.keyvault.spring;

import com.microsoft.azure.AzureResponseBuilder;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.serializer.AzureJacksonAdapter;
import com.microsoft.azure.spring.support.UserAgent;
import com.microsoft.azure.telemetry.TelemetryData;
import com.microsoft.azure.telemetry.TelemetryProxy;
import com.microsoft.rest.RestClient;
import com.microsoft.rest.credentials.ServiceClientCredentials;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.util.HashMap;

class KeyVaultEnvironmentPostProcessorHelper {

    private final ConfigurableEnvironment environment;
    private final TelemetryProxy telemetryProxy;

    public KeyVaultEnvironmentPostProcessorHelper(ConfigurableEnvironment environment) {
        this.environment = environment;
        this.telemetryProxy = new TelemetryProxy(this.allowTelemetry(environment));
    }

    public void addKeyVaultPropertySource() {
        final String clientId = getProperty(environment, Constants.AZURE_CLIENTID);
        final String clientKey = getProperty(environment, Constants.AZURE_CLIENTKEY);
        final String vaultUri = getProperty(environment, Constants.AZURE_KEYVAULT_VAULT_URI);

        final long timeAcquiringTimeoutInSeconds = environment.getProperty(
                Constants.AZURE_TOKEN_ACQUIRE_TIMEOUT_IN_SECONDS, Long.class, 60L);

        final ServiceClientCredentials credentials =
                new AzureKeyVaultCredential(clientId, clientKey, timeAcquiringTimeoutInSeconds);
        final RestClient restClient = new RestClient.Builder().withBaseUrl(vaultUri)
                .withCredentials(credentials)
                .withSerializerAdapter(new AzureJacksonAdapter())
                .withResponseBuilderFactory(new AzureResponseBuilder.Factory())
                .withUserAgent(UserAgent.getUserAgent(Constants.AZURE_KEYVAULT_USER_AGENT,
                        allowTelemetry(environment)))
                .build();

        final KeyVaultClient kvClient = new KeyVaultClient(restClient);

        this.trackCustomEvent();

        try {
            final MutablePropertySources sources = environment.getPropertySources();
            final KeyVaultOperation kvOperation = new KeyVaultOperation(kvClient, vaultUri);

            if (sources.contains(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME)) {
                sources.addAfter(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                        new KeyVaultPropertySource(kvOperation));
            } else {
                sources.addFirst(new KeyVaultPropertySource(kvOperation));
            }

        } catch (Exception ex) {
            throw new IllegalStateException("Failed to configure KeyVault property source", ex);
        }
    }

    private String getProperty(ConfigurableEnvironment env, String propertyName) {
        Assert.notNull(env, "env must not be null!");
        Assert.notNull(propertyName, "propertyName must not be null!");

        final String property = env.getProperty(propertyName);

        if (property == null || property.isEmpty()) {
            throw new IllegalArgumentException("property " + propertyName + " must not be null");
        }
        return property;
    }

    private boolean allowTelemetry(ConfigurableEnvironment env) {
        Assert.notNull(env, "env must not be null!");

        return env.getProperty(Constants.AZURE_KEYVAULT_ALLOW_TELEMETRY, Boolean.class, true);
    }

    private void trackCustomEvent() {
        final HashMap<String, String> customTelemetryProperties = new HashMap<>();
        customTelemetryProperties.put(TelemetryData.SERVICE_NAME, "keyvault");

        telemetryProxy.trackEvent(ClassUtils.getUserClass(this.getClass()).getSimpleName(), customTelemetryProperties);
    }
}
