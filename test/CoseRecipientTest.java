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

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.google.common.base.VerifyException;
import com.google.common.collect.ImmutableList;
import java.util.List;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CoseRecipientTest {

  @Test
  public void encodeAndDecodeCoseRecipient() throws Exception {
    byte[] protectedHeaders = "serialized protected headers".getBytes(UTF_8);
    Map unprotectedHeaders = buildUnprotectedHeaders();
    byte[] ciphertext = "ciphertext".getBytes(UTF_8);

    byte[] encodedRecipient =
        new CoseRecipient(protectedHeaders, unprotectedHeaders, ciphertext).encode();
    CoseRecipient decodedRecipient = CoseRecipient.decode(encodedRecipient);

    assertThat(decodedRecipient.getProtectedHeaders()).isEqualTo(protectedHeaders);
    assertThat(decodedRecipient.getUnprotectedHeaders()).isEqualTo(unprotectedHeaders);
    assertThat(decodedRecipient.getCiphertext()).isEqualTo(ciphertext);
  }

  @Test
  public void decodeCborByteString_shouldWork() throws Exception {
    byte[] encodedRecipient =
        new byte[] {
          -125, 80, 112, 114, 111, 116, 101, 99, 116, 101, 100, 72, 101, 97, 100, 101, 114, 115,
          -95, 5, 66, 105, 118, 74, 99, 105, 112, 104, 101, 114, 116, 101, 120, 116
        };

    CoseRecipient decodedRecipient = CoseRecipient.decode(encodedRecipient);

    assertThat(decodedRecipient.getProtectedHeaders())
        .isEqualTo("protectedHeaders".getBytes(UTF_8));
    assertThat(decodedRecipient.getUnprotectedHeaders())
        .isEqualTo(new CborBuilder().addMap().put(5, "iv".getBytes(UTF_8)).end().build().get(0));
    assertThat(decodedRecipient.getCiphertext()).isEqualTo("ciphertext".getBytes(UTF_8));
  }

  @Test
  public void decodeRandomBytes_shouldFail() {
    byte[] encodedRecipient = new byte[] {-125, 80, 112, 114, 111, 116, 101};
    assertThrows(VerifyException.class, () -> CoseRecipient.decode(encodedRecipient));
  }

  public static Map buildUnprotectedHeaders() throws CborException {
    int alg = 1;
    List<Integer> labels = ImmutableList.of(1, 2, 3);
    int contentType = 1;
    byte[] kid = "kid".getBytes(UTF_8);
    byte[] iv = "iv".getBytes(UTF_8);
    byte[] partialIv = "partialIc".getBytes(UTF_8);
    byte[] coseSignature = "coseSignature".getBytes(UTF_8);

    DataItem unprotectedHeaders =
        CoseUtil.buildUnprotectedHeader(
            Optional.of(alg),
            Optional.of(labels),
            Optional.of(contentType),
            Optional.of(kid),
            Optional.of(iv),
            Optional.of(partialIv),
            Optional.of(coseSignature));
    return CborUtil.asMap(unprotectedHeaders);
  }
}
