/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kafka.common.utils;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.config.SecurityConfig;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SecurityProviderCreator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Security;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

// DECISION: Centralized security utility class for principal parsing, ACL enum mapping, and
// security provider registration. Alternative: Distribute these utilities to each security
// subpackage. Rationale: Shared parsing logic (toPascalCase, valueFromMap) is used by both
// client-side (ResourceType, AclOperation) and server-side (StandardAuthorizer) -- centralizing
// avoids duplication and ensures consistent behavior across the security stack.
//
// CROSS-CUTTING: Consumed by metadata/authorizer/StandardAuthorizer for ACL enum resolution,
// by clients/admin/KafkaAdminClient for ACL management requests, and by core/server/AuthHelper
// for principal construction. The security provider registration is called during broker
// initialization (core/BrokerServer, core/ControllerServer).
public class SecurityUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityUtils.class);

    private static final Map<String, ResourceType> NAME_TO_RESOURCE_TYPES;
    private static final Map<String, AclOperation> NAME_TO_OPERATIONS;
    private static final Map<String, AclPermissionType> NAME_TO_PERMISSION_TYPES;

    // DECISION: Eagerly-built case-insensitive lookup maps for ResourceType, AclOperation,
    // and AclPermissionType at class-load time. Each enum value is stored in both PascalCase
    // and UPPERCASE forms. Alternative: Dynamic case conversion on each lookup. Rationale:
    // ACL authorization is on the hot path -- O(1) map lookup is significantly faster than
    // iterating enum values with case-insensitive string comparison. The dual-key approach
    // handles both human-readable (PascalCase) and machine-generated (UPPERCASE) inputs.
    static {
        NAME_TO_RESOURCE_TYPES = new HashMap<>(ResourceType.values().length);
        NAME_TO_OPERATIONS = new HashMap<>(AclOperation.values().length);
        NAME_TO_PERMISSION_TYPES = new HashMap<>(AclPermissionType.values().length);

        for (ResourceType resourceType : ResourceType.values()) {
            String resourceTypeName = toPascalCase(resourceType.name());
            NAME_TO_RESOURCE_TYPES.put(resourceTypeName, resourceType);
            NAME_TO_RESOURCE_TYPES.put(resourceTypeName.toUpperCase(Locale.ROOT), resourceType);
        }
        for (AclOperation operation : AclOperation.values()) {
            String operationName = toPascalCase(operation.name());
            NAME_TO_OPERATIONS.put(operationName, operation);
            NAME_TO_OPERATIONS.put(operationName.toUpperCase(Locale.ROOT), operation);
        }
        for (AclPermissionType permissionType : AclPermissionType.values()) {
            String permissionName  = toPascalCase(permissionType.name());
            NAME_TO_PERMISSION_TYPES.put(permissionName, permissionType);
            NAME_TO_PERMISSION_TYPES.put(permissionName.toUpperCase(Locale.ROOT), permissionType);
        }
    }

    // DECISION: Splits on first colon only (limit=2) to support principal names containing
    // colons (e.g., Kerberos principals "User:admin@REALM"). Alternative: Split all colons.
    // Rationale: Kerberos principal format "primaryName/instance@REALM" may contain colons
    // in the name portion.
    public static KafkaPrincipal parseKafkaPrincipal(String str) {
        if (str == null || str.isEmpty()) {
            throw new IllegalArgumentException("expected a string in format principalType:principalName but got " + str);
        }

        String[] split = str.split(":", 2);

        if (split.length != 2) {
            throw new IllegalArgumentException("expected a string in format principalType:principalName but got " + str);
        }

        return new KafkaPrincipal(split[0], split[1]);
    }

    // SECURITY: Dynamically registers java.security.Provider implementations via reflection.
    // Risk: A malicious SecurityProviderCreator class could register a compromised provider
    // that intercepts cryptographic operations (e.g., weak PRNG, backdoored cipher). The
    // provider is inserted at position (index+1), giving it higher priority than defaults.
    // Mitigation: Only classes specified in the broker config are loaded.
    // Improvement: Consider validating the loaded class against an allowlist of known
    // SecurityProviderCreator implementations, and logging provider registration for audit.
    public static void addConfiguredSecurityProviders(Map<String, ?> configs) {
        String securityProviderClassesStr = (String) configs.get(SecurityConfig.SECURITY_PROVIDERS_CONFIG);
        if (securityProviderClassesStr == null || securityProviderClassesStr.isEmpty()) {
            return;
        }
        try {
            String[] securityProviderClasses = securityProviderClassesStr.replaceAll("\\s+", "").split(",");
            for (int index = 0; index < securityProviderClasses.length; index++) {
                SecurityProviderCreator securityProviderCreator =
                    (SecurityProviderCreator) Class.forName(securityProviderClasses[index]).getConstructor().newInstance();
                securityProviderCreator.configure(configs);
                // SECURITY: insertProviderAt(position) determines provider priority --
                // lower positions are checked first. Inserting at index+1 means
                // user-configured providers take precedence over JDK defaults. This is
                // intentional (enables custom TLS providers) but requires trust in the
                // configured provider classes.
                Security.insertProviderAt(securityProviderCreator.getProvider(), index + 1);
            }
        } catch (ClassCastException e) {
            LOGGER.error("Creators provided through " + SecurityConfig.SECURITY_PROVIDERS_CONFIG +
                    " are expected to be sub-classes of SecurityProviderCreator");
        } catch (ClassNotFoundException cnfe) {
            LOGGER.error("Unrecognized security provider creator class", cnfe);
        } catch (ReflectiveOperationException e) {
            LOGGER.error("Unexpected implementation of security provider creator class", e);
        }
    }

    public static ResourceType resourceType(String name) {
        return valueFromMap(NAME_TO_RESOURCE_TYPES, name, ResourceType.UNKNOWN);
    }

    public static AclOperation operation(String name) {
        return valueFromMap(NAME_TO_OPERATIONS, name, AclOperation.UNKNOWN);
    }

    public static AclPermissionType permissionType(String name) {
        return valueFromMap(NAME_TO_PERMISSION_TYPES, name, AclPermissionType.UNKNOWN);
    }

    // DECISION: Two-phase lookup: first exact match (PascalCase), then uppercase fallback.
    // Rationale: PascalCase is the expected format from API calls -- avoiding toUpperCase()
    // for the common case saves a String allocation per lookup.
    //
    // We use Pascal-case to store these values, so lookup using provided key first to avoid
    // case conversion for the common case. For backward compatibility, also perform
    // case-insensitive look up (without underscores) by converting the key to upper-case.
    private static <T> T valueFromMap(Map<String, T> map, String key, T unknown) {
        T value = map.get(key);
        if (value == null) {
            value = map.get(key.toUpperCase(Locale.ROOT));
        }
        return value == null ? unknown : value;
    }

    public static String resourceTypeName(ResourceType resourceType) {
        return toPascalCase(resourceType.name());
    }

    public static String operationName(AclOperation operation) {
        return toPascalCase(operation.name());
    }

    public static String permissionTypeName(AclPermissionType permissionType) {
        return toPascalCase(permissionType.name());
    }

    private static String toPascalCase(String name) {
        StringBuilder builder = new StringBuilder();
        boolean capitalizeNext = true;
        for (char c : name.toCharArray()) {
            if (c == '_')
                capitalizeNext = true;
            else if (capitalizeNext) {
                builder.append(Character.toUpperCase(c));
                capitalizeNext = false;
            } else
                builder.append(Character.toLowerCase(c));
        }
        return builder.toString();
    }

    // SECURITY: Input validation for authorization queries. Rejects ANY and UNKNOWN values
    // which are filter types, not concrete resource/operation types. Allowing ANY could
    // cause authorization checks to match unintended resources. Risk: If this validation
    // were bypassed, a caller could query "ANY resource, ANY operation" and receive a
    // blanket authorization result.
    public static void authorizeByResourceTypeCheckArgs(AclOperation op,
                                                        ResourceType type) {
        if (type == ResourceType.ANY) {
            throw new IllegalArgumentException(
                "Must specify a non-filter resource type for authorizeByResourceType");
        }

        if (type == ResourceType.UNKNOWN) {
            throw new IllegalArgumentException(
                "Unknown resource type");
        }

        if (op == AclOperation.ANY) {
            throw new IllegalArgumentException(
                "Must specify a non-filter operation type for authorizeByResourceType");
        }

        if (op == AclOperation.UNKNOWN) {
            throw new IllegalArgumentException(
                "Unknown operation type");
        }
    }
}
