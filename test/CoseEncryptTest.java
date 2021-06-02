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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CoseEncryptTest {

  @Test
  public void encodeAndDecodeCoseEncrypt() throws Exception {
    byte[] protectedHeaders = "serialized protected headers".getBytes(UTF_8);
    Map unprotectedHeaders = buildUnprotectedHeader();
    byte[] ciphertext = "ciphertext".getBytes(UTF_8);
    byte[] encodedRecipient =
        new byte[] {
          -125, 80, 112, 114, 111, 116, 101, 99, 116, 101, 100, 72, 101, 97, 100, 101, 114, 115,
          -95, 5, 66, 105, 118, 74, 99, 105, 112, 104, 101, 114, 116, 101, 120, 116
        };
    List<byte[]> recipients = ImmutableList.of(encodedRecipient);

    byte[] encodedEncrypt =
        new CoseEncrypt(protectedHeaders, unprotectedHeaders, ciphertext, recipients).encode();
    CoseEncrypt decodedEncrypt = CoseEncrypt.decode(encodedEncrypt);

    assertThat(decodedEncrypt.getProtectedHeaders()).isEqualTo(protectedHeaders);
    assertThat(decodedEncrypt.getUnprotectedHeaders()).isEqualTo(unprotectedHeaders);
    assertThat(decodedEncrypt.getCiphertext()).isEqualTo(ciphertext);
    assertThat(decodedEncrypt.getRecipients()).hasSize(1);
    assertThat(decodedEncrypt.getRecipients().get(0)).isEqualTo(encodedRecipient);
  }

  @Test
  public void decodeCborByteString_shouldWork() throws CborException {
    byte[] encoded =
        new byte[] {
          -124, 80, 112, 114, 111, 116, 101, 99, 116, 101, 100, 72, 101, 97, 100, 101, 114, 115,
          -95, 5, 66, 105, 118, 74, 99, 105, 112, 104, 101, 114, 116, 101, 120, 116, -128
        };

    CoseEncrypt decodedEncrypt = CoseEncrypt.decode(encoded);

    assertThat(decodedEncrypt.getProtectedHeaders()).isEqualTo("protectedHeaders".getBytes(UTF_8));
    assertThat(decodedEncrypt.getUnprotectedHeaders())
        .isEqualTo(new CborBuilder().addMap().put(5, "iv".getBytes(UTF_8)).end().build().get(0));
    assertThat(decodedEncrypt.getCiphertext()).isEqualTo("ciphertext".getBytes(UTF_8));
    assertThat(decodedEncrypt.getRecipients()).isEmpty();
  }

  @Test
  public void decodeRandomBytes_shouldFail() {
    byte[] encodedEncrypt = new byte[] {101, 99, 116, 101, 100, 72, 101, 97, 100, 101};
    assertThrows(VerifyException.class, () -> CoseEncrypt.decode(encodedEncrypt));
  }

  private static Map buildUnprotectedHeader() throws CborException {
    DataItem unprotectedHeaders =
        new CborBuilder().addMap().put(5, "iv".getBytes(UTF_8)).end().build().get(0);
    return CborUtil.asMap(unprotectedHeaders);
  }
}
