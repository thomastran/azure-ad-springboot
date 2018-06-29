/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.microsoft.azure.spring.autoconfigure.documentdb;

import com.microsoft.azure.documentdb.ConnectionMode;
import com.microsoft.azure.documentdb.ConsistencyLevel;
import com.microsoft.azure.documentdb.MediaReadMode;
import com.microsoft.azure.utils.PropertyLoader;

import java.util.Arrays;
import java.util.List;

public class PropertySettingUtil {
    public static final String URI = "https://test.documents.azure.com:443/";
    public static final String KEY = "KeyString";
    public static final boolean ALLOW_TELEMETRY_TRUE = true;
    public static final boolean ALLOW_TELEMETRY_FALSE = false;
    public static final ConsistencyLevel CONSISTENCY_LEVEL = ConsistencyLevel.Strong;
    public static final int REQUEST_TIMEOUT = 4;
    public static final int MEDIA_REQUEST_TIMEOUT = 3;
    public static final ConnectionMode CONNECTION_MODE = ConnectionMode.DirectHttps;
    public static final MediaReadMode MEDIA_READ_MODE = MediaReadMode.Streamed;
    public static final int MAX_POOL_SIZE = 1;
    public static final int IDLE_CONNECTION_TIMEOUT = 2;
    public static final String USER_AGENT_SUFFIX = "suffix";
    public static final String DEFAULT_USER_AGENT_SUFFIX = "spring-boot-starter/" + PropertyLoader.getProjectVersion();
    public static final int RETRY_OPTIONS_MAX_RETRY_ATTEMPTS_ON_THROTTLED_REQUESTS = 5;
    public static final int RETRY_OPTIONS_MAX_RETRY_WAIT_TIME_IN_SECONDS = 6;
    public static final boolean ENABLE_ENDPOINT_DISCOVERY = false;
    public static final List<String> PREFERRED_LOCATIONS = Arrays.asList("East US", "West US", "North Europe");
    private static final String PROPERTY_URI = "azure.documentdb.uri";
    private static final String PROPERTY_KEY = "azure.documentdb.key";
    private static final String PROPERTY_CONSISTENCY_LEVEL = "azure.documentdb.consistency-level";
    private static final String PROPERTY_ALLOW_TELEMETRY = "azure.documentdb.allow-telemetry";

    public static void setProperties() {
        System.setProperty(PROPERTY_URI, URI);
        System.setProperty(PROPERTY_KEY, KEY);
        System.setProperty(PROPERTY_CONSISTENCY_LEVEL, CONSISTENCY_LEVEL.name());
        System.setProperty(PROPERTY_ALLOW_TELEMETRY, Boolean.toString(ALLOW_TELEMETRY_TRUE));
    }

    public static void setAllowTelemetryFalse() {
        setProperties();
        System.setProperty(PROPERTY_ALLOW_TELEMETRY, Boolean.toString(ALLOW_TELEMETRY_FALSE));
    }

    public static void unsetProperties() {
        System.clearProperty(PROPERTY_URI);
        System.clearProperty(PROPERTY_KEY);
        System.clearProperty(PROPERTY_CONSISTENCY_LEVEL);
        System.clearProperty(PROPERTY_ALLOW_TELEMETRY);
    }

    public static void unsetAllowTelemetry() {
        System.clearProperty(PROPERTY_ALLOW_TELEMETRY);
    }
}
