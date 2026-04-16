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
package org.apache.kafka.common.network;

import org.apache.kafka.common.Reconfigurable;

// DECISION: Extends Reconfigurable with a listenerName() method to enable per-listener
// dynamic reconfiguration. This is used by SslChannelBuilder and SaslChannelBuilder to
// support dynamic SSL certificate rotation and SASL configuration updates on a per-listener
// basis without broker restart.
// Alternative: Single global Reconfigurable — rejected because different listeners may have
// different SSL certificates and SASL configurations that need independent reconfiguration.
// The listenerName() enables DynamicBrokerConfig (core/) to route reconfiguration events
// to the correct ChannelBuilder.

// CROSS-CUTTING: Consumed by DynamicBrokerConfig in core/src/main/scala/kafka/server/ which
// manages runtime configuration changes. Implementations: SslChannelBuilder, SaslChannelBuilder.
// Contract: reconfigure() must be atomic — either fully applied or rolled back.

/**
 * Interface for reconfigurable entities associated with a listener.
 */
public interface ListenerReconfigurable extends Reconfigurable {

    /**
     * Returns the listener name associated with this reconfigurable. Listener-specific
     * configs corresponding to this listener name are provided for reconfiguration.
     */
    ListenerName listenerName();
}
