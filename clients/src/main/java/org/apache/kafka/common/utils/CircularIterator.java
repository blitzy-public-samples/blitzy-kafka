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

import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.Objects;

/**
 * An iterator that cycles through the {@code Iterator} of a {@code Collection}
 * indefinitely. Useful for tasks such as round-robin load balancing. This class
 * does not provide thread-safe access. This {@code Iterator} supports
 * {@code null} elements in the underlying {@code Collection}. This
 * {@code Iterator} does not support any modification to the underlying
 * {@code Collection} after it has been wrapped by this class. Changing the
 * underlying {@code Collection} may cause a
 * {@link ConcurrentModificationException} or some other undefined behavior.
 */
// DECISION: Infinite round-robin iterator with peek() support. Alternative: Modular index
// tracking (index % size). Rationale: Encapsulating circular iteration in an Iterator type
// enables composition with iterator-based APIs. peek() enables look-ahead without advancing,
// which is used for request distribution decisions.
// CROSS-CUTTING: Used by producer internals for round-robin partition assignment and by
// network layer for distributing requests across available brokers.
public class CircularIterator<T> implements Iterator<T> {

    private final Iterable<T> iterable;
    private Iterator<T> iterator;
    private T nextValue;

    /**
     * Create a new instance of a CircularIterator. The ordering of this
     * Iterator will be dictated by the Iterator returned by Collection itself.
     *
     * @param col The collection to iterate indefinitely
     *
     * @throws NullPointerException if col is {@code null}
     * @throws IllegalArgumentException if col is empty.
     */
    public CircularIterator(final Collection<T> col) {
        this.iterable = Objects.requireNonNull(col);
        this.iterator = col.iterator();
        if (col.isEmpty()) {
            throw new IllegalArgumentException("CircularIterator can only be used on non-empty lists");
        }
        this.nextValue = advance();
    }

    /**
     * Returns true since the iteration will forever cycle through the provided
     * {@code Collection}.
     *
     * @return Always true
     */
    // DECISION: Always returns true (infinite iteration) — callers must use external termination
    // condition. Alternative: Fixed iteration count. Rationale: Round-robin distribution needs
    // to cycle indefinitely; callers control how many iterations they need.
    @Override
    public boolean hasNext() {
        return true;
    }

    @Override
    public T next() {
        final T next = nextValue;
        nextValue = advance();
        return next;
    }

    /**
     * Return the next value in the {@code Iterator}, restarting the
     * {@code Iterator} if necessary.
     *
     * @return The next value in the iterator
     */
    private T advance() {
        if (!iterator.hasNext()) {
            iterator = iterable.iterator();
        }
        return iterator.next();
    }

    /**
     * Peek at the next value in the Iterator. Calling this method multiple
     * times will return the same element without advancing this Iterator. The
     * value returned by this method will be the next item returned by
     * {@code next()}.
     *
     * @return The next value in this {@code Iterator}
     */
    public T peek() {
        return nextValue;
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException();
    }
}
