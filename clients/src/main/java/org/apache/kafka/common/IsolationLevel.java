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
package org.apache.kafka.common;

import java.util.Locale;

/**
 * Defines the transaction isolation semantics for reading records from a topic partition.
 *
 * @implNote DECISION: Two isolation levels (READ_UNCOMMITTED=0, READ_COMMITTED=1) model
 * transactional semantics introduced in KIP-98. Alternative considered: a simple boolean flag
 * (committed vs. uncommitted). Rationale: an enum with explicit numeric IDs is extensible for
 * potential future isolation levels and maps directly to the FetchRequest protocol field, avoiding
 * a breaking protocol change if a third level is ever added.
 *
 * <p>CROSS-CUTTING: Used by consumer FetchRequest construction (clients module), FetchSession
 * handling (core/server), and server-side FetchDataInfo filtering in ReplicaManager. The isolation
 * level determines whether uncommitted transactional records are visible to the consumer.
 */
public enum IsolationLevel {
    // DECISION: READ_UNCOMMITTED (default) returns all records including uncommitted transactional
    // records for backward compatibility. READ_COMMITTED returns only committed transactional records
    // and all non-transactional records, requiring the consumer to track LSO (Last Stable Offset).
    READ_UNCOMMITTED((byte) 0), READ_COMMITTED((byte) 1);

    private final byte id;

    IsolationLevel(byte id) {
        this.id = id;
    }

    public byte id() {
        return id;
    }

    public static IsolationLevel forId(byte id) {
        switch (id) {
            case 0:
                return READ_UNCOMMITTED;
            case 1:
                return READ_COMMITTED;
            default:
                throw new IllegalArgumentException("Unknown isolation level " + id);
        }
    }

    @Override
    public String toString() {
        return super.toString().toLowerCase(Locale.ROOT);
    }
}
