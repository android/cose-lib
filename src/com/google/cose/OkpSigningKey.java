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
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Sign.KeyPair;
import com.google.crypto.tink.subtle.Ed25519Verify;
import java.security.GeneralSecurityException;

/**
 * Implements OKP COSE_Key spec for signing purposes.
 * Currently only supports Ed25519 curve.
 */
public final class OkpSigningKey extends OkpKey {
  private byte[] privateKeyBytes;
  private byte[] publicKeyBytes;

  public OkpSigningKey(DataItem cborKey) throws CborException, CoseException {
    super(cborKey);

    int curve = CborUtils.asInteger(labels.get(Headers.KEY_PARAMETER_CURVE));
    if (curve != Headers.CURVE_OKP_ED25519) {
      throw new CoseException(CoseException.UNSUPPORTED_CURVE_EXCEPTION_MESSAGE);
    }

    populateKeyFromCbor();

    if ((operations != null)
        && !operations.contains(Headers.KEY_OPERATIONS_VERIFY)
        && !operations.contains(Headers.KEY_OPERATIONS_SIGN)) {
      throw new CoseException("Signing key requires either sign or verify operation.");
    }
  }

  @Override
  void populateKeyFromCbor() throws CborException, CoseException {
    privateKeyBytes = getPrivateKeyBytesFromCbor();
    publicKeyBytes = getPublicKeyBytesFromCbor();
  }

  private byte[] getPrivateKeyBytesFromCbor() throws CborException, CoseException {
    if (labels.containsKey(Headers.KEY_PARAMETER_D)) {
      byte[] keyMaterial = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_D)).getBytes();
      if (keyMaterial.length == 0) {
        throw new CoseException("Could not decode private key. Expected key material.");
      }
      return keyMaterial;
    }
    return null;
  }

  private byte[] getPublicKeyBytesFromCbor() throws CborException, CoseException {
    if (labels.containsKey(Headers.KEY_PARAMETER_X)) {
      byte[] keyMaterial = CborUtils.asByteString(labels.get(Headers.KEY_PARAMETER_X)).getBytes();
      if (keyMaterial.length == 0) {
        throw new CoseException("Could not decode public key. Expected key material.");
      }
      return keyMaterial;
    }
    if (privateKeyBytes == null) {
      throw new CoseException(CoseException.MISSING_KEY_MATERIAL_EXCEPTION_MESSAGE);
    }
    try {
      return KeyPair.newKeyPairFromSeed(privateKeyBytes).getPublicKey();
    } catch (GeneralSecurityException e) {
      throw new CoseException("Error while generating public key from private key bytes.", e);
    }
  }

  public static OkpSigningKey parse(byte[] keyBytes) throws CborException, CoseException {
    DataItem dataItem = CborUtils.decode(keyBytes);
    return decode(dataItem);
  }

  public static OkpSigningKey decode(DataItem cborKey) throws CborException, CoseException {
    return new OkpSigningKey(cborKey);
  }

  /** Generates a COSE formatted OKP signing key from scratch */
  public static OkpSigningKey generateKey() throws CborException, CoseException {
    KeyPair keyPair;
    try {
      keyPair = KeyPair.newKeyPair();
    } catch (GeneralSecurityException e) {
      throw new CoseException("Error while signing message.", e);
    }
    byte[] privateKey = keyPair.getPrivateKey();
    byte[] publicKey = keyPair.getPublicKey();

    return OkpSigningKey.builder().withXCoordinate(publicKey).withDParameter(privateKey).build();
  }

  public static class Builder extends OkpKey.Builder<Builder> {
    private byte[] dParameter;

    @Override
    public Builder self() {
      return this;
    }

    @Override
    boolean isKeyMaterialPresent() {
      return (dParameter != null && dParameter.length != 0) || super.isKeyMaterialPresent();
    }

    @Override
    public Builder withOperations(Integer...operations) throws CoseException {
      for (int operation : operations) {
        if (operation != Headers.KEY_OPERATIONS_SIGN
            && operation != Headers.KEY_OPERATIONS_VERIFY) {
          throw new CoseException("Signing key only supports Sign or Verify operations.");
        }
      }
      return super.withOperations(operations);
    }

    @Override
    public OkpSigningKey build() throws CborException, CoseException {
      withCurve(Headers.CURVE_OKP_ED25519);

      Map cborKey = compile();
      if (dParameter != null) {
        cborKey.put(new NegativeInteger(Headers.KEY_PARAMETER_D), new ByteString(dParameter));
      }
      return new OkpSigningKey(cborKey);
    }

    public Builder withDParameter(byte[] dParam) {
      this.dParameter = dParam;
      return this;
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  public byte[] sign(Algorithm algorithm, byte[] message) throws CborException, CoseException {
    if (privateKeyBytes == null) {
      throw new CoseException("Missing key material for signing.");
    }
    if (algorithm != Algorithm.SIGNING_ALGORITHM_EDDSA) {
      throw new CoseException("Incompatible key type.");
    }
    verifyAlgorithmMatchesKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_SIGN);
    return tinkSign(message);
  }

  private byte[] tinkSign(byte[] message) throws CoseException {
    try {
      Ed25519Sign signer = new Ed25519Sign(privateKeyBytes);
      return signer.sign(message);
    } catch (GeneralSecurityException e) {
      throw new CoseException("Error while signing message.", e);
    }
  }

  public void verify(Algorithm algorithm, byte[] message, byte[] signature)
      throws CborException, CoseException {
    if (algorithm != Algorithm.SIGNING_ALGORITHM_EDDSA) {
      throw new CoseException("Incompatible key type.");
    }
    verifyAlgorithmMatchesKey(algorithm);
    verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_VERIFY);
    tinkVerify(signature, message);
  }

  private void tinkVerify(byte[] signature, byte[] message) throws CoseException {
    try {
      Ed25519Verify verifier = new Ed25519Verify(publicKeyBytes);
      verifier.verify(signature, message);
    } catch (GeneralSecurityException e) {
      throw new CoseException("Error while verifying message.", e);
    }
  }
}
