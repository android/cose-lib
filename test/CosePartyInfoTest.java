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
public class CosePartyInfoTest {

  @Test
  public void encodeAndDecodeCosePartyInfo() throws Exception {
    byte[] identity = "identity".getBytes(UTF_8);
    byte[] nonce = "nonce".getBytes(UTF_8);
    byte[] other = "pubkey".getBytes(UTF_8);

    byte[] encodedPartyInfo = new CosePartyInfo(identity, nonce, other).encode();
    CosePartyInfo decodedPartyInfo = CosePartyInfo.decode(encodedPartyInfo);

    assertThat(decodedPartyInfo.getIdentity()).isEqualTo(identity);
    assertThat(decodedPartyInfo.getNonce()).isEqualTo(nonce);
    assertThat(decodedPartyInfo.getOther()).isEqualTo(other);
  }

  @Test
  public void decodeCborByteString_shouldWork() throws CborException {
    byte[] encodedPartyInfo =
        new byte[] {
          -125, 72, 105, 100, 101, 110, 116, 105, 116, 121, 69, 110, 111, 110, 99, 101, 70, 112,
          117, 98, 107, 101, 121
        };

    CosePartyInfo decodedPartyInfo = CosePartyInfo.decode(encodedPartyInfo);

    assertThat(decodedPartyInfo.getIdentity()).isEqualTo("identity".getBytes(UTF_8));
    assertThat(decodedPartyInfo.getNonce()).isEqualTo("nonce".getBytes(UTF_8));
    assertThat(decodedPartyInfo.getOther()).isEqualTo("pubkey".getBytes(UTF_8));
  }

  @Test
  public void decodeRandomBytes_shouldFail() {
    byte[] encodedPartyInfo = new byte[] {-125, 72, 105, 100, 101, 110, 116, 105};
    assertThrows(VerifyException.class, () -> CosePartyInfo.decode(encodedPartyInfo));
  }
}
