package com.google.cose;

import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.utils.CborUtils;
import java.util.Collections;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MacMessageTest {
  @Test
  public void testDeserialize() {
    MacMessage message = MacMessage.deserialize(TestUtilities.hexStringToByteArray(
      "8543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91"
          + "F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440"
    ));
    Assert.assertEquals(TestUtilities.CONTENT, new String(message.getMessage()));
    Assert.assertEquals("A10105",
        TestUtilities.bytesToHexString(message.getProtectedHeaderBytes()));
    Assert.assertEquals(0, message.getUnprotectedHeaders().getKeys().size());
    Assert.assertEquals("2BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6",
        TestUtilities.bytesToHexString(message.getTag()));
    Assert.assertEquals(1, message.recipients.size());

    Recipient r = message.recipients.get(0);
    Assert.assertEquals("", TestUtilities.bytesToHexString(r.getProtectedHeaderBytes()));
    Assert.assertEquals(new NegativeInteger(-6),
        r.getUnprotectedHeaders().get(new UnsignedInteger(1)));
    Assert.assertEquals(new ByteString(TestUtilities.hexStringToByteArray("6F75722D736563726574")),
        r.getUnprotectedHeaders().get(new UnsignedInteger(4)));
    Assert.assertEquals("", TestUtilities.bytesToHexString(r.getCiphertext()));
  }

  @Test
  public void testSerialize() {
    Map protectedHeaders = new Map();
    protectedHeaders.put(new UnsignedInteger(1), new UnsignedInteger(5));

    Map unprotectedHeaders = new Map();
    unprotectedHeaders.put(new UnsignedInteger(1), new NegativeInteger(-6));
    unprotectedHeaders.put(new UnsignedInteger(4),
        new ByteString(TestUtilities.hexStringToByteArray("6F75722D736563726574")));

    Recipient r = Recipient.builder()
        .withCiphertext(new byte[0])
        .withUnprotectedHeaders(unprotectedHeaders)
        .withProtectedHeaderBytes(new byte[0])
        .build();

    MacMessage message = MacMessage.builder()
        .withProtectedHeaderBytes(CborUtils.encode(protectedHeaders))
        .withUnprotectedHeaders(new Map())
        .withMessage(TestUtilities.CONTENT.getBytes())
        .withTag(TestUtilities.hexStringToByteArray(
            "2BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6"))
        .withRecipients(Collections.singletonList(r))
        .build();

    Assert.assertEquals("8340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(r.serialize()));

    Assert.assertEquals("8543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B"
        + "8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6818340A20125044A6F75722D73656372657440",
        TestUtilities.bytesToHexString(message.serialize()));
  }
}
