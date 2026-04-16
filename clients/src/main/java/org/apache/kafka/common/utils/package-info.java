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
/**
 * Provides common utilities for Kafka server and clients.
 * <strong>This package is not a supported Kafka API; the implementation may change without warning between minor or patch releases.</strong>
 */
// DECISION: This package is marked as internal (non-public API) -- classes here may change
// without notice between Kafka versions. Alternative: Expose utilities as public API.
// Rationale: Keeping utils internal prevents external callers from depending on implementation
// details that may change (e.g., buffer pooling strategy, iterator patterns), while allowing
// rapid internal evolution.
//
// CROSS-CUTTING: This package is the most widely-imported package across all Kafka modules.
// Utils, Time, Timer, ByteUtils, LogContext, and Bytes are imported by virtually every
// module in the repository (clients, core, streams, connect, metadata, storage, coordinator,
// raft, tools).
package org.apache.kafka.common.utils;