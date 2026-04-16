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

import java.util.Locale;

// DECISION: Static OS detection at class-load time. Uses System.getProperty("os.name") with
// uppercase comparison for platform-gated behaviors (e.g., directory fsync is skipped on Windows
// per KAFKA-13391, and on z/OS). Alternative: Runtime.getRuntime().exec("uname"). Rationale:
// System property is reliable, fast, and doesn't spawn a subprocess.
//
// CROSS-CUTTING: Consumed by Utils.flushDir() to skip fsync on Windows/z/OS, and by test
// utilities for platform-specific test behavior. IS_WINDOWS and IS_ZOS are the primary flags.
public final class OperatingSystem {

    private OperatingSystem() {
    }
    
    public static final String NAME;

    public static final boolean IS_WINDOWS;

    public static final boolean IS_ZOS;

    static {
        NAME = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        IS_WINDOWS = NAME.startsWith("windows");
        IS_ZOS = NAME.startsWith("z/os");
    }
}
