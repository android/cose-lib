package com.google.cose.structure;

import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.TestUtilities;
import com.google.cose.structures.SignStructure;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SignStructureTest {
  @Test
  public void testHappyCase() {
    String context = "Signature";
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
}
