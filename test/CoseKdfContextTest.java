/*
 * Copyright 2020 Google LLC
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

package cose;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import co.nstant.in.cbor.CborException;
import com.google.common.base.VerifyException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CoseKdfContextTest {

  @Test
  public void encodeAndDecodeCoseKdfContext() throws Exception {
    int alg = 1;
    byte[] partyU = "encoded partyU".getBytes(UTF_8);
    byte[] partyV = "encoded partyV".getBytes(UTF_8);
    byte[] suppPubInfo = "suppPubInfo".getBytes(UTF_8);

    byte[] encodedKdfContext = new CoseKdfContext(alg, partyU, partyV, suppPubInfo).encode();
    CoseKdfContext decodedKdfContext = CoseKdfContext.decode(encodedKdfContext);

    assertThat(decodedKdfContext.getAlg()).isEqualTo(alg);
    assertThat(decodedKdfContext.getPartyU()).isEqualTo(partyU);
    assertThat(decodedKdfContext.getPartyV()).isEqualTo(partyV);
    assertThat(decodedKdfContext.getSuppPubInfo()).isEqualTo(suppPubInfo);
  }

  @Test
  public void decodeCborByteString_shouldWork() throws CborException {
    byte[] encodedKdfContext =
        new byte[] {
          -124, 1, 78, 101, 110, 99, 111, 100, 101, 100, 32, 112, 97, 114, 116, 121, 85, 78, 101,
          110, 99, 111, 100, 101, 100, 32, 112, 97, 114, 116, 121, 86, 75, 115, 117, 112, 112, 80,
          117, 98, 73, 110, 102, 111
        };

    CoseKdfContext decodedKdfContext = CoseKdfContext.decode(encodedKdfContext);

    assertThat(decodedKdfContext.getAlg()).isEqualTo(1);
    assertThat(decodedKdfContext.getPartyU()).isEqualTo("encoded partyU".getBytes(UTF_8));
    assertThat(decodedKdfContext.getPartyV()).isEqualTo("encoded partyV".getBytes(UTF_8));
    assertThat(decodedKdfContext.getSuppPubInfo()).isEqualTo("suppPubInfo".getBytes(UTF_8));
  }

  @Test
  public void decodeRandomBytes_shouldFail() {
    byte[] encodedKdfContext = new byte[] {-91, 1, 1, 2, 67, 107, 105, 100};
    assertThrows(VerifyException.class, () -> CoseKdfContext.decode(encodedKdfContext));
  }
}
