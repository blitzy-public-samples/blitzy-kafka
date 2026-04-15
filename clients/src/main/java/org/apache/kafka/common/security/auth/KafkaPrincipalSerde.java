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
package org.apache.kafka.common.security.auth;

import org.apache.kafka.common.errors.SerializationException;

/**
 * Serializer/Deserializer interface for {@link KafkaPrincipal} for the purpose of inter-broker forwarding.
 * Any serialization/deserialization failure should raise a {@link SerializationException} to be consistent.
 */
// SECURITY: (MEDIUM) Principal serialization/deserialization for inter-broker forwarding.
// Why: When a broker forwards a request to the controller (e.g., CreateTopics to the active
// controller), the client's KafkaPrincipal must be serialized, transmitted over the network,
// and deserialized at the destination with fidelity. The deserialized principal is used for
// authorization decisions at the controller.
// Exploit: If the serde does not validate the deserialized principal's type and name fields,
// a compromised broker could forge arbitrary principal identities in forwarded requests,
// effectively bypassing ACL checks at the controller. For example, serializing a principal
// with type "User" and name "admin" when the original client was "User:anonymous".
// Improvement: Consider adding integrity verification (e.g., HMAC over serialized bytes
// using an inter-broker shared secret) to detect tampered principal data in forwarded requests.
//
// CROSS-CUTTING: Extended by KafkaPrincipalBuilder (this package) -- every principal builder
// also serves as a serde. Used by core/server for serializing principals in forwarded requests
// to the controller, and by the controller for deserializing principals from forwarded requests.
// Contract: serialize()/deserialize() must be inverse operations -- deserialize(serialize(p))
// must produce a KafkaPrincipal equal to p. SerializationException on failure.
// Impact: Incompatible serde changes between broker versions break request forwarding.
public interface KafkaPrincipalSerde {

    /**
     * Serialize a {@link KafkaPrincipal} into byte array.
     *
     * @param principal principal to be serialized
     * @return serialized bytes
     * @throws SerializationException
     */
    byte[] serialize(KafkaPrincipal principal) throws SerializationException;

    /**
     * Deserialize a {@link KafkaPrincipal} from byte array.
     * @param bytes byte array to be deserialized
     * @return the deserialized principal
     * @throws SerializationException
     */
    KafkaPrincipal deserialize(byte[] bytes) throws SerializationException;
}
