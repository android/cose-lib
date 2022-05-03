package com.google.cose.structure;

import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.TestUtilities;
import com.google.cose.structures.MacStructure;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.Headers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MacStructureTest {
  @Test
  public void testMac0Structure() {
    String context = "MAC0";
    Map headers = new Map();
    headers.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getAlgorithmId());
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT.getBytes();
    MacStructure m = new MacStructure(context, headers, externalAad, payload);
    Assert.assertEquals(
        "84644D41433043A101054054546869732069732074686520636F6E74656E742E",
        TestUtilities.bytesToHexString(m.serialize())
    );
  }

  @Test
  public void testMacStructure() {
    String context = "MAC";
    Map headers = new Map();
    headers.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.MAC_ALGORITHM_HMAC_SHA_256_256.getAlgorithmId());
    byte[] externalAad = new byte[0];
    byte[] payload = TestUtilities.CONTENT.getBytes();
    MacStructure m = new MacStructure(context, headers, externalAad, payload);
    Assert.assertEquals(
        "84634D414343A101054054546869732069732074686520636F6E74656E742E",
        TestUtilities.bytesToHexString(m.serialize())
    );
  }
}
