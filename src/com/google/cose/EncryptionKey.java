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

package com.google.cose;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Implements COSE_Key spec for encryption purposes. */
public final class EncryptionKey extends CoseKey {
  private final byte[] secretKey;

  public EncryptionKey(final DataItem cborKey) throws CborException, CoseException {
    super(cborKey);
    if (labels.containsKey(Headers.KEY_PARAMETER_K)
        && labels.get(Headers.KEY_PARAMETER_K).getMajorType() == MajorType.BYTE_STRING) {
      byte[] keyMaterial = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_K)).getBytes();
      if (keyMaterial.length == 0) {
        throw new CoseException("Missing key material information.");
      } else {
        secretKey = keyMaterial;
      }
    } else {
      throw new CoseException("Missing key material information.");
    }

    if ((operations != null)
        && !operations.contains(Headers.KEY_OPERATIONS_DECRYPT)
        && !operations.contains(Headers.KEY_OPERATIONS_ENCRYPT)) {
      throw new CoseException("Encryption key requires either encrypt or decrypt operation.");
    }
  }

  public static EncryptionKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static EncryptionKey decode(DataItem cborKey) throws CborException, CoseException {
    return new EncryptionKey(cborKey);
  }

  public static class Builder extends CoseKey.Builder<Builder> {
    private byte[] secretKey;

    @Override
    Builder self() {
      return this;
    }

    @Override
    void verifyKeyMaterialPresentAndComplete() throws CoseException {
      if (secretKey == null) {
        throw new CoseException("Missing key material information.");
      }
    }

    @Override
    public EncryptionKey build() throws CborException, CoseException {
      withKeyType(Headers.KEY_TYPE_SYMMETRIC);
      Map cborKey = compile();

      cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_K), new ByteString(secretKey));
      return new EncryptionKey(cborKey);
    }

    @Override
    public Builder withOperations(Integer...operations) throws CoseException {
      for (int operation : operations) {
        if (operation != Headers.KEY_OPERATIONS_ENCRYPT && operation != Headers.KEY_OPERATIONS_DECRYPT)
          throw new CoseException("Encryption key only supports Encrypt or Decrypt operations.");
      }
      return super.withOperations(operations);
    }

    public Builder withSecretKey(byte[] k) {
      this.secretKey = k;
      return this;
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  private byte[] aesGcmCipher(int mode, Algorithm algorithm, byte[] message, byte[] iv, byte[] aad)
      throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
      InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(16 * 8, iv);
    cipher.init(mode, new SecretKeySpec(secretKey, algorithm.getJavaAlgorithmId()),
        gcmSpec);
    if (aad != null) {
      cipher.updateAAD(aad);
    }
    return cipher.doFinal(message);
  }

  public byte[] encrypt(Algorithm algorithm, byte[] message, byte[] iv, byte[] aad)
      throws CborException, CoseException {
    verifyAlgorithmMatchesKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_ENCRYPT);
    try {
      return aesGcmCipher(Cipher.ENCRYPT_MODE, algorithm, message, iv, aad);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException
        | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      throw new CoseException("Error while encrypting message.", e);
    }
  }

  public byte[] decrypt(Algorithm algorithm, byte[] ciphertext, byte[] iv, byte[] aad)
      throws CborException, CoseException {
    verifyAlgorithmMatchesKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_DECRYPT);
    try {
      return aesGcmCipher(Cipher.DECRYPT_MODE, algorithm, ciphertext, iv, aad);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException
        | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      throw new CoseException("Error while decrypting message.", e);
    }
  }
}
