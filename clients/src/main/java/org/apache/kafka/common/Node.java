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

import java.util.Objects;

/**
 * Information about a Kafka node
 *
 * @implNote DECISION: Mutable-ish value type representing a broker endpoint. Uses lazy-cached
 * hashCode (Integer field {@code hash}) and pre-computed {@code idString}. Alternative: Fully
 * immutable with eager hashCode. Rationale: Node instances are created frequently during
 * metadata updates and used as map keys in performance-sensitive paths
 * (RecordAccumulator.ready, NetworkClient.leastLoadedNode) — lazy hash avoids computation
 * when not used as key; pre-computed idString avoids repeated Integer.toString() in
 * logging/debug paths.
 */
// CROSS-CUTTING: Most widely-used broker identity type across ALL Kafka modules. Consumed by
// Cluster (node indexing), NetworkClient (connection management), Metadata (leader tracking),
// RecordAccumulator (partition-to-node mapping), and all admin/consumer/producer request
// routing. Also used in streams/ for task assignment and connect/ for worker coordination.
public class Node {

    // DECISION: Sentinel NO_NODE with id=-1 represents "no broker available" rather than
    // using null. Alternative: Optional<Node>. Rationale: Sentinel avoids NullPointerException
    // in chained calls and predates Optional's introduction. Used by Cluster.leaderFor() and
    // leastLoadedNode().
    private static final Node NO_NODE = new Node(-1, "", -1);

    private final int id;
    private final String idString;
    private final String host;
    private final int port;
    private final String rack;
    // DECISION: Fenced flag (KIP-841) indicates broker is in controlled shutdown or
    // pre-start. Alternative: Separate FencedNode subclass. Rationale: Inline boolean avoids
    // type hierarchy complexity; fenced brokers are still valid network targets for certain
    // operations.
    private final boolean isFenced;

    // Cache hashCode as it is called in performance sensitive parts of the code (e.g. RecordAccumulator.ready)
    // DECISION: Integer (boxed) rather than int to use null as "not yet computed" sentinel.
    // Benign race on concurrent lazy init produces same value.
    private Integer hash;

    public Node(int id, String host, int port) {
        this(id, host, port, null, false);
    }

    public Node(int id, String host, int port, String rack) {
        this.id = id;
        this.idString = Integer.toString(id);
        this.host = host;
        this.port = port;
        this.rack = rack;
        this.isFenced = false;
    }

    public Node(int id, String host, int port, String rack, boolean isFenced) {
        this.id = id;
        this.idString = Integer.toString(id);
        this.host = host;
        this.port = port;
        this.rack = rack;
        this.isFenced = isFenced;
    }

    public static Node noNode() {
        return NO_NODE;
    }

    /**
     * Check whether this node is empty, which may be the case if noNode() is used as a placeholder
     * in a response payload with an error.
     * @return true if it is, false otherwise
     */
    public boolean isEmpty() {
        return host == null || host.isEmpty() || port < 0;
    }

    /**
     * The node id of this node
     */
    public int id() {
        return id;
    }

    /**
     * String representation of the node id.
     * Typically the integer id is used to serialize over the wire, the string representation is used as an identifier with NetworkClient code
     */
    public String idString() {
        return idString;
    }

    /**
     * The host name for this node
     */
    public String host() {
        return host;
    }

    /**
     * The port for this node
     */
    public int port() {
        return port;
    }

    /**
     * True if this node has a defined rack
     */
    public boolean hasRack() {
        return rack != null;
    }

    /**
     * The rack for this node
     */
    public String rack() {
        return rack;
    }

    /**
     * Returns whether this node is fenced.
     * <p>
     * This applies to broker nodes only. For controller quorum nodes, this field
     * is not relevant and is defined to be {@code false}.
     */
    public boolean isFenced() {
        return isFenced;
    }

    @Override
    public int hashCode() {
        Integer h = this.hash;
        if (h == null) {
            int result = 31 + ((host == null) ? 0 : host.hashCode());
            result = 31 * result + id;
            result = 31 * result + port;
            result = 31 * result + ((rack == null) ? 0 : rack.hashCode());
            result = 31 * result + Objects.hashCode(isFenced);
            this.hash = result;
            return result;
        } else {
            return h;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;
        Node other = (Node) obj;
        return id == other.id &&
            port == other.port &&
            Objects.equals(host, other.host) &&
            Objects.equals(rack, other.rack) &&
            Objects.equals(isFenced, other.isFenced);
    }

    @Override
    public String toString() {
        return host + ":" + port + " (id: " + idString + " rack: " + rack + " isFenced: " + isFenced + ")";
    }

}
