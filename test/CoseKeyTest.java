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
import com.google.common.collect.ImmutableList;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CoseKeyTest {

  @Test
  public void encodeAndDecodeCoseKey() throws Exception {
    int kty = 1;
    byte[] kid = "kid".getBytes(UTF_8);
    int alg = 2;
    ImmutableList<Integer> keyOps = ImmutableList.of(1, 2, 3);
    byte[] baseIv = "baseIv".getBytes(UTF_8);

    byte[] encodedKey = new CoseKey(kty, kid, alg, keyOps, baseIv).encode();
    CoseKey decodedKey = CoseKey.decode(encodedKey);

    assertThat(decodedKey.getKeyType()).isEqualTo(kty);
    assertThat(decodedKey.getKeyId()).isEqualTo(kid);
    assertThat(decodedKey.getAlg()).isEqualTo(alg);
    assertThat(decodedKey.getKeyOps()).isEqualTo(keyOps);
    assertThat(decodedKey.getBaseIv()).isEqualTo(baseIv);
  }

  @Test
  public void decodeCborByteString_shouldWork() throws CborException {
    byte[] encodedKey =
        new byte[] {
          -91, 1, 1, 2, 67, 107, 105, 100, 3, 2, 4, -125, 1, 2, 3, 5, 70, 98, 97, 115, 101, 73, 118
        };

    CoseKey decodedKey = CoseKey.decode(encodedKey);

    assertThat(decodedKey.getKeyType()).isEqualTo(1);
    assertThat(decodedKey.getKeyId()).isEqualTo("kid".getBytes(UTF_8));
    assertThat(decodedKey.getAlg()).isEqualTo(2);
    assertThat(decodedKey.getKeyOps()).containsExactly(1, 2, 3).inOrder();
    assertThat(decodedKey.getBaseIv()).isEqualTo("baseIv".getBytes(UTF_8));
  }

  @Test
  public void decodeRandomBytes_shouldFail() {
    byte[] encodedKey = new byte[] {-91, 1, 1, 2, 67, 107, 105, 100};
    assertThrows(VerifyException.class, () -> CoseKey.decode(encodedKey));
  }
}
