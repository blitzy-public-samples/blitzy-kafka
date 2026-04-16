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

import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * A base class that simplifies implementing an iterator
 * @param <T> The type of thing we are iterating over
 */
// DECISION: State-machine-based lazy iterator (READY/NOT_READY/DONE/FAILED) following Guava's
// AbstractIterator pattern. Alternative: Force subclasses to manage hasNext/next state directly.
// Rationale: State machine ensures consistent hasNext()/next()/peek() semantics and prevents
// common iterator bugs (double-advance, returning null after exhaustion). NOT thread-safe by design
// — Kafka iterators are used in single-threaded processing loops.
// CROSS-CUTTING: Base iterator used across clients/, streams/, and server modules for lazy
// iteration over log segments, fetch results, partition data, and record batches. Subclassed
// in 20+ locations throughout the Kafka codebase.
public abstract class AbstractIterator<T> implements Iterator<T> {

    // DECISION: FAILED state prevents use-after-error. Once makeNext() throws, the iterator is
    // permanently poisoned. Alternative: Allow retry after exception. Rationale: Fail-fast
    // prevents silent data corruption if iterator state is inconsistent after an error.
    private enum State {
        READY, NOT_READY, DONE, FAILED
    }

    private State state = State.NOT_READY;
    private T next;

    @Override
    public boolean hasNext() {
        switch (state) {
            case FAILED:
                throw new IllegalStateException("Iterator is in failed state");
            case DONE:
                return false;
            case READY:
                return true;
            default:
                return maybeComputeNext();
        }
    }

    @Override
    public T next() {
        if (!hasNext())
            throw new NoSuchElementException();
        state = State.NOT_READY;
        if (next == null)
            throw new IllegalStateException("Expected item but none found.");
        return next;
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("Removal not supported");
    }

    public T peek() {
        if (!hasNext())
            throw new NoSuchElementException();
        return next;
    }

    protected T allDone() {
        state = State.DONE;
        return null;
    }

    protected abstract T makeNext();

    // DECISION: Sets state to FAILED before calling makeNext(), then to READY on success.
    // This ensures that if makeNext() throws, the iterator transitions to FAILED rather than
    // remaining in NOT_READY (which could cause infinite hasNext() loops).
    private Boolean maybeComputeNext() {
        state = State.FAILED;
        next = makeNext();
        if (state == State.DONE) {
            return false;
        } else {
            state = State.READY;
            return true;
        }
    }

}
