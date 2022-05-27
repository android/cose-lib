/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.cose;

import com.google.common.collect.ImmutableList;
import java.util.List;

/**
 * Implements COSE_KeySet. Just has a bunch of keys but would remain majorly untouched till we
 * have a proper use case.
 */
public class CoseKeySet {
  private final ImmutableList<CoseKey> coseKeys;

  public CoseKeySet(List<CoseKey> coseKeys) {
    this.coseKeys = ImmutableList.copyOf(coseKeys);
  }

  public List<CoseKey> getKeys() {
    return coseKeys;
  }
}
