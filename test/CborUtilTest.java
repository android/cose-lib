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
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CborUtilTest {

  @Test
  public void encode_shouldBeDecoded() {
    DataItem dataItem =
        new CborBuilder()
            .addArray()
            .add("foo")
            .add(true)
            .addArray()
            .add(42)
            .add(43)
            .end()
            .add(new byte[] {0x01, 0x02})
            .end()
            .build()
            .get(0);

    byte[] encoded = CborUtil.encode(dataItem);

    DataItem decoded = CborUtil.cborToDataItem(encoded);
    assertThat(decoded).isEqualTo(dataItem);
  }

  @Test
  public void decodeMap_shouldWork() throws Exception {
    DataItem mapDataItem = new CborBuilder().addMap().put("key", "value").end().build().get(0);
    Map decodedMap = CborUtil.asMap(mapDataItem);

    assertThat(decodedMap).isEqualTo(mapDataItem);
  }

  @Test
  public void decodeMap_wrongType_shouldThrowException() throws Exception {
    DataItem arrayDataItem = new CborBuilder().addArray().add("value").end().build().get(0);

    CborException ex = assertThrows(CborException.class, () -> CborUtil.asMap(arrayDataItem));
    assertThat(ex).hasMessageThat().contains("Expected a map, got ARRAY");
  }

  @Test
  public void decodeArray_shouldWork() throws Exception {
    DataItem arrayDataItem = new CborBuilder().addArray().add("value").end().build().get(0);
    Array decodedArray = CborUtil.asArray(arrayDataItem);

    assertThat(decodedArray).isEqualTo(arrayDataItem);
  }

  @Test
  public void decodeArray_wrongType_shouldThrowException() {
    DataItem stringDataItem = new CborBuilder().add("string value").build().get(0);

    CborException ex = assertThrows(CborException.class, () -> CborUtil.asArray(stringDataItem));
    assertThat(ex).hasMessageThat().contains("Expected an array, got UNICODE_STRING");
  }

  @Test
  public void decodeByteString_shouldWork() throws Exception {
    DataItem byteStringDataItem =
        new CborBuilder().add("byteString value".getBytes(UTF_8)).build().get(0);
    ByteString decodedByteString = CborUtil.asByteString(byteStringDataItem);

    assertThat(decodedByteString).isEqualTo(byteStringDataItem);
  }

  @Test
  public void decodeByteString_wrongType_shouldThrowException() {
    DataItem stringDataItem = new CborBuilder().add("string value").build().get(0);

    CborException ex =
        assertThrows(CborException.class, () -> CborUtil.asByteString(stringDataItem));
    assertThat(ex).hasMessageThat().contains("Expected a byte string, got UNICODE_STRING");
  }

  @Test
  public void decodeNumber_shouldWork() throws Exception {
    DataItem numberDataItem = new CborBuilder().add(123).build().get(0);
    int decodedNumber = CborUtil.asNumber(numberDataItem);

    assertThat(decodedNumber).isEqualTo(123);
  }

  @Test
  public void decodeNumber_wrongType_shouldThrowException() {
    DataItem stringDataItem = new CborBuilder().add("string value").build().get(0);

    CborException ex = assertThrows(CborException.class, () -> CborUtil.asNumber(stringDataItem));
    assertThat(ex).hasMessageThat().contains("Invalid type: UNICODE_STRING");
  }
}
