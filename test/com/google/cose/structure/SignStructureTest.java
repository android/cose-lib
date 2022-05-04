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
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.TestUtilities;
import com.google.cose.structures.SignStructure;
import com.google.cose.structures.SignStructure.SignatureContext;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SignStructureTest {
  @Test
  public void testSignStructure() throws CborException {
    SignatureContext context = SignatureContext.SIGNATURE;
    Map protectedSignHeaders = new Map();
    protectedSignHeaders.put(new UnsignedInteger(1), new NegativeInteger(-7));
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT.getBytes();
    SignStructure s = new SignStructure(context, new Map(), protectedSignHeaders, externalAad,
        payload);
    Assert.assertEquals(
        "85695369676E61747572654043A101264054546869732069732074686520636F6E74656E742E",
        TestUtilities.bytesToHexString(s.serialize())
    );
  }

  @Test
  public void testSign1Structure() throws CborException {
    SignatureContext context = SignatureContext.SIGNATURE1;
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT.getBytes();
    SignStructure s = new SignStructure(context, new Map(), null, externalAad, payload);
    Assert.assertEquals(
        "846A5369676E617475726531404054546869732069732074686520636F6E74656E742E",
        TestUtilities.bytesToHexString(s.serialize())
    );
  }
}
