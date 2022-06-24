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
import com.google.cose.structure.EncryptStructure.EncryptionContext;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class EncryptStructureTest {
  @Test
  public void testEncrypt0StructureEncoding() throws CborException {
    EncryptionContext context = EncryptionContext.ENCRYPT0;
    Map headers = new Map();
    byte[] externalAad = new byte[0];
    EncryptStructure structure = new EncryptStructure(context, headers, externalAad);
    List<DataItem> cborArrayItems = CborUtils.asArray(structure.encode()).getDataItems();
    Assert.assertEquals(3, cborArrayItems.size());
    Assert.assertEquals(context.getContext(), CborUtils.getString(cborArrayItems.get(0)));
    Assert.assertEquals(0, CborUtils.getBytes(cborArrayItems.get(1)).length);
    Assert.assertArrayEquals(externalAad, CborUtils.getBytes(cborArrayItems.get(2)));
  }

  @Test
  public void testEncrypt0StructureSerialization() throws CborException {
    EncryptionContext context = EncryptionContext.ENCRYPT0;
    Map headers = new Map();
    byte[] externalAad = new byte[0];
    EncryptStructure structure = new EncryptStructure(context, headers, externalAad);
    Assert.assertEquals("8368456E6372797074304040",
        TestUtilities.bytesToHexString(structure.serialize())
    );
  }

  @Test
  public void testEncryptStructureEncoding() throws CborException {
    EncryptionContext context = EncryptionContext.ENCRYPT;
    Map headers = new Map();
    headers.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.ENCRYPTION_AES_128_GCM.getCoseAlgorithmId());
    byte[] externalAad = "AadContent".getBytes(StandardCharsets.UTF_8);
    EncryptStructure structure = new EncryptStructure(context, headers, externalAad);
    List<DataItem> cborArrayItems = CborUtils.getDataItems(structure.encode());
    Assert.assertEquals(3, cborArrayItems.size());
    Assert.assertEquals(context.getContext(), CborUtils.getString(cborArrayItems.get(0)));
    Assert.assertArrayEquals(TestUtilities.hexStringToByteArray("A10101"),
        CborUtils.getBytes(cborArrayItems.get(1)));
    Assert.assertArrayEquals(externalAad, CborUtils.getBytes(cborArrayItems.get(2)));
  }

  @Test
  public void testEncryptStructureSerialization() throws CborException {
    EncryptionContext context = EncryptionContext.ENCRYPT;
    Map headers = new Map();
    headers.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.ENCRYPTION_AES_128_GCM.getCoseAlgorithmId());
    byte[] externalAad = new byte[0];
    EncryptStructure structure = new EncryptStructure(context, headers, externalAad);
    Assert.assertEquals("8367456E637279707443A1010140",
        TestUtilities.bytesToHexString(structure.serialize())
    );
  }
}
