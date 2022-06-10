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
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.TestUtilities;
import com.google.cose.structure.SignStructure.SignatureContext;
import com.google.cose.utils.CborUtils;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SignStructureTest {
  @Test
  public void testSignStructureSerialization() throws CborException {
    SignatureContext context = SignatureContext.SIGNATURE;
    Map protectedSignHeaders = new Map();
    protectedSignHeaders.put(new UnsignedInteger(1), new NegativeInteger(-7));
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT_BYTES;
    SignStructure s = new SignStructure(context, new Map(), protectedSignHeaders, externalAad,
        payload);
    Assert.assertEquals(
        "85695369676E61747572654043A101264054546869732069732074686520636F6E74656E742E",
        TestUtilities.bytesToHexString(s.serialize())
    );
  }

  @Test
  public void testSignStructureEncoding() throws CborException {
    SignatureContext context = SignatureContext.SIGNATURE;
    Map protectedSignHeaders = new Map();
    protectedSignHeaders.put(new UnsignedInteger(1), new NegativeInteger(-7));
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT_BYTES;
    SignStructure structure = new SignStructure(context, new Map(), protectedSignHeaders,
        externalAad, payload);
    List<DataItem> cborArrayItems = CborUtils.getDataItems(structure.encode());
    Assert.assertEquals(5, cborArrayItems.size());
    Assert.assertEquals(context.getContext(), CborUtils.getString(cborArrayItems.get(0)));
    Assert.assertEquals(0, CborUtils.getBytes(cborArrayItems.get(1)).length);
    Assert.assertArrayEquals(TestUtilities.hexStringToByteArray("A10126"),
        CborUtils.getBytes(cborArrayItems.get(2)));
    Assert.assertEquals(externalAad, CborUtils.getBytes(cborArrayItems.get(3)));
    Assert.assertEquals(payload, CborUtils.getBytes(cborArrayItems.get(4)));
  }

  @Test
  public void testSign1StructureSerialization() throws CborException {
    SignatureContext context = SignatureContext.SIGNATURE1;
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT_BYTES;
    SignStructure s = new SignStructure(context, new Map(), null, externalAad, payload);
    Assert.assertEquals(
        "846A5369676E617475726531404054546869732069732074686520636F6E74656E742E",
        TestUtilities.bytesToHexString(s.serialize())
    );
  }

  @Test
  public void testSign1StructureEncoding() throws CborException {
    SignatureContext context = SignatureContext.SIGNATURE1;
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT_BYTES;
    SignStructure structure = new SignStructure(context, new Map(), null, externalAad, payload);
    List<DataItem> cborArrayItems = CborUtils.getDataItems(structure.encode());
    Assert.assertEquals(4, cborArrayItems.size());
    Assert.assertEquals(context.getContext(), CborUtils.getString(cborArrayItems.get(0)));
    Assert.assertEquals(0, CborUtils.getBytes(cborArrayItems.get(1)).length);
    Assert.assertEquals(externalAad, CborUtils.getBytes(cborArrayItems.get(2)));
    Assert.assertEquals(payload, CborUtils.getBytes(cborArrayItems.get(3)));
  }
}
