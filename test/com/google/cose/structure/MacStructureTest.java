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

package com.google.cose.structure;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.TestUtilities;
import com.google.cose.structure.MacStructure.MacContext;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MacStructureTest {
  @Test
  public void testMac0StructureSerialization() throws CborException {
    MacContext context = MacContext.MAC0;
    Map headers = new Map();
    headers.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId());
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT.getBytes();
    MacStructure structure = new MacStructure(context, headers, externalAad, payload);
    Assert.assertEquals(
        "84644D41433043A101054054546869732069732074686520636F6E74656E742E",
        TestUtilities.bytesToHexString(structure.serialize())
    );
  }

  @Test
  public void testMac0StructureEncoding() throws CborException {
    MacContext context = MacContext.MAC0;
    Map headers = new Map();
    headers.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId());
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT.getBytes();
    MacStructure structure = new MacStructure(context, headers, externalAad, payload);
    List<DataItem> cborArrayItems = CborUtils.asArray(structure.encode()).getDataItems();
    Assert.assertEquals(4, cborArrayItems.size());
    Assert.assertEquals(context.getContext(),
        CborUtils.asUnicodeString(cborArrayItems.get(0)).toString());
    Assert.assertArrayEquals(TestUtilities.hexStringToByteArray("A10105"),
        CborUtils.asByteString(cborArrayItems.get(1)).getBytes());
    Assert.assertEquals(externalAad, CborUtils.asByteString(cborArrayItems.get(2)).getBytes());
    Assert.assertEquals(payload, CborUtils.asByteString(cborArrayItems.get(3)).getBytes());
  }

  @Test
  public void testMacStructureSerialization() throws CborException {
    MacContext context = MacContext.MAC;
    Map headers = new Map();
    headers.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId());
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT.getBytes();
    MacStructure structure = new MacStructure(context, headers, externalAad, payload);
    Assert.assertEquals(
        "84634D414343A101054054546869732069732074686520636F6E74656E742E",
        TestUtilities.bytesToHexString(structure.serialize())
    );
  }

  @Test
  public void testMacStructureEncoding() throws CborException {
    MacContext context = MacContext.MAC;
    Map headers = new Map();
    headers.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getCoseAlgorithmId());
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT.getBytes();
    MacStructure structure = new MacStructure(context, headers, externalAad, payload);
    List<DataItem> cborArrayItems = CborUtils.asArray(structure.encode()).getDataItems();
    Assert.assertEquals(4, cborArrayItems.size());
    Assert.assertEquals(context.getContext(),
        CborUtils.asUnicodeString(cborArrayItems.get(0)).toString());
    Assert.assertArrayEquals(TestUtilities.hexStringToByteArray("A10105"),
        CborUtils.asByteString(cborArrayItems.get(1)).getBytes());
    Assert.assertEquals(externalAad, CborUtils.asByteString(cborArrayItems.get(2)).getBytes());
    Assert.assertEquals(payload, CborUtils.asByteString(cborArrayItems.get(3)).getBytes());
  }
}
