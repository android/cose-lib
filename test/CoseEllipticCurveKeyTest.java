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
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CoseEllipticCurveKeyTest {

  @Test
  public void encodeAndDecodeCoseEcKey() throws Exception {
    byte[] x = "x".getBytes(UTF_8);
    byte[] d = "d".getBytes(UTF_8);

    byte[] encodedEcKey = new CoseEllipticCurveKey(x, Optional.of(d)).encode();
    CoseEllipticCurveKey decodedEcKey = CoseEllipticCurveKey.decode(encodedEcKey);

    assertThat(decodedEcKey.getX()).isEqualTo(x);
    assertThat(decodedEcKey.getD().get()).isEqualTo(d);
  }

  @Test
  public void encodeAndDecodeCoseEcKey_emptyD() throws Exception {
    byte[] x = "x".getBytes(UTF_8);

    byte[] encodedEcKey = new CoseEllipticCurveKey(x, Optional.empty()).encode();
    CoseEllipticCurveKey decodedEcKey = CoseEllipticCurveKey.decode(encodedEcKey);

    assertThat(decodedEcKey.getX()).isEqualTo(x);
    assertThat(decodedEcKey.getD()).isEqualTo(Optional.empty());
  }

  @Test
  public void decodeCborByteString_shouldWork() throws CborException {
    byte[] encodedEcKey = new byte[] {-92, 1, 1, 32, 6, 33, 65, 120, 35, 65, 100};

    CoseEllipticCurveKey decodedEcKey = CoseEllipticCurveKey.decode(encodedEcKey);

    assertThat(decodedEcKey.getX()).isEqualTo("x".getBytes(UTF_8));
    assertThat(decodedEcKey.getD().get()).isEqualTo("d".getBytes(UTF_8));
  }

  @Test
  public void decodeRandomBytes_shouldFail() {
    byte[] encodedEcKey = new byte[] {-92, 1, 1, 32, 6, 33};
    assertThrows(VerifyException.class, () -> CoseKey.decode(encodedEcKey));
  }
}
