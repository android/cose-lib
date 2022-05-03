package com.google.cose.structure;

import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.TestUtilities;
import com.google.cose.structures.EncryptStructure;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.Headers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class EncryptStructureTest {
  @Test
  public void testEncrypt0Structure() {
    String context = "Encrypt0";
    Map headers = new Map();
    byte[] externalAad = new byte[0];
    EncryptStructure s = new EncryptStructure(context, headers, externalAad);
    Assert.assertEquals("8368456E6372797074304040",
        TestUtilities.bytesToHexString(s.serialize())
    );
  }

  @Test
  public void testEncryptStructure() {
    String context = "Encrypt";
    Map headers = new Map();
    headers.put(new UnsignedInteger(Headers.MESSAGE_HEADER_ALGORITHM),
        Algorithm.ENCRYPTION_AES_128_GCM.getAlgorithmId());
    byte[] externalAad = new byte[0];
    EncryptStructure s = new EncryptStructure(context, headers, externalAad);
    Assert.assertEquals("8367456E637279707443A1010140",
        TestUtilities.bytesToHexString(s.serialize())
    );
  }
}
