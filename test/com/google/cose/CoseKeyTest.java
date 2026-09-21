/*
 * Copyright 2026 Google LLC
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

import static com.google.common.truth.Truth.assertThat;

import co.nstant.in.cbor.CborException;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class CoseKeyTest {

  @Before
  public void setUp() {
    Security.addProvider(Conscrypt.newProvider());
  }

  @Test
  public void testGenerateOkpSigningKey() throws CborException, CoseException {
    CoseKey key = CoseKey.generateKey(Algorithm.SIGNING_ALGORITHM_EDDSA);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(OkpSigningKey.class);
  }

  @Test
  public void testGenerateAkpSigningKey() throws CborException, CoseException {
    CoseKey key = CoseKey.generateKey(Algorithm.SIGNING_ALGORITHM_MLDSA_87);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(AkpSigningKey.class);
  }

  @Test
  public void testGenerateEc2SigningKey() throws CborException, CoseException {
    CoseKey key = CoseKey.generateKey(Algorithm.SIGNING_ALGORITHM_ECDSA_SHA_256);
    assertThat(key).isNotNull();
    assertThat(key).isInstanceOf(Ec2SigningKey.class);
  }
}
