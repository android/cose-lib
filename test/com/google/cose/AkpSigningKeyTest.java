/*
 * Copyright 2026 Google LLC
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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.google.cose.exceptions.CoseException;
import com.google.cose.utils.Algorithm;
import com.google.cose.utils.CborUtils;
import com.google.cose.utils.Headers;
import java.security.Provider;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test class for testing {@link AkpSigningKey}. */
@RunWith(JUnit4.class)
public class AkpSigningKeyTest {
  private static final String COSE_ENCODED_MLDSA87_KEY =
      "A50107025820D9BC439F97BD6D4093E68F0F3FCF09C9A97ADF888ED7308DD565247A166CB4FA03383120590A20E"
          + "45FFC8CC73DB885DC662E62A18CD8E3803297117FA5658814A985B5FF1DB7B468CFC82BB929F1D86B77ED"
          + "14F5AE16A65368772CE51912410105E0456975AE91FDB643B512F124D5E60BD68B8C7E31FE01C7B0DC65A"
          + "E470501CC565A6E1DFCFCFD12565433C4AFEDD511821E2E9610C45275E2836DEE35CED69D7EFA672FD1E4"
          + "318BEF5EB6E897E8B451AA202DED042B2AAEF77A7BE3F699146DA229A8BDB3FFA496445967E75217BFBC9"
          + "048F9956443D8731F833EB30DE10DAC96FFFE7CF65EA0445C3E31E8601E133BE6A100764FE3196E267726"
          + "441F31751FBF9A6F5880644F4E7275E57DE2B0F105E4DB055D50DD1C9C934FDDF535B8DE28B0C74C0449F"
          + "222CD2ED0BB8FBC775CCEE8C940665B40F712F4F7E00750E9E1E4CD9CFF25D1945C3E9BCA53CCD4F12EEE"
          + "7581856EBD68F26845956E3E7BEB761F0FE75BDD31BFE2FA018113397B387BD59D62A68B8AF7FA245AB93"
          + "2E69F778E2CEEFD21304FBB8099EA13D8EA57C1813197A2F75AE251075B51DAD38F853669E9D5F98A3655"
          + "098941993A1594860FBA71FE530EE5C29F58F2978AF688CCB75A5838A359C112E98E25A8583AC8DAC1F86"
          + "1FD58E2AFBA5DE5A52E020904F5B42BC0874E35BEFCF3E6119684768F36E008F04712177CEBE627607381"
          + "E56EAAEE161C1729B8DE51DBDE474D48CC68249EA27162B87993E60C84ED6CC6423CB3676D9EB50B2CAB5"
          + "A3A049EF131381D623FA6FBCBC9DB1E7CC025EA0418B9DAD2CC6CCD4E95FA2CEC24FEECA70318A751716B"
          + "7213F63EDBF65A63338357F838F94EC071822C24851248885107B3D1C4E924678C7614EA1AF038104619F"
          + "2AE372940BECFA69E29CBB5FF6C3E20A47BE4A4F74BAC34C133C00A6A706ACCC6FFD3D8E4FBD69A99704E"
          + "1283C850D8C58D1E5753CD9587B83C4C346CB9A58137213EC10834C66ADFE2BB5C501A8EF2ECADD1B677A"
          + "3DF1A6DEB86EBF0722C4F5030E20F9018DD5B6FC53EEA24FD92B7B5B4025FEAE996D3E48FD4C650D82DBA"
          + "D7EAF936639698512F26253D2EF6847C8518E8565CC9A5495C6FFF57CDE7323882C54A7DB470AB2DAF8FF"
          + "D2BF794FA7C692D9E7FBD532EECC1D7880E2CA0B3216128BE28B4A9F1D151FAC97808B0BD98B7B43A612A"
          + "9AC865812BFEAC6F47460277840B52A3B087F916CA7CEDC0F768EA2BD19EA21155F84B4A04C4000AD2AE0"
          + "587154D560BC0A477A4F9329A8984DD31EB1F2A05E3D918701D630CFCA9AF61EF088D2C5581ACB463E439"
          + "902E5D425719E956B8D6DF7305B28E0FF27D3AD0DE2085D292499B19A3390D4396FB3BAC9A8D8CBEAD2A7"
          + "A4290FC9AC6FCA045F98A614A45A39CBE24360F84D14F8E472712ACEB74DBF45B53D49A0E4737E476FFC4"
          + "D5B2F7CD247AA186D3B764AD9E9CFEEE456A73C291D8DE3912414AC43911C372173AD7B472AF35C6853CE"
          + "D2FE7B5FE0A89565AB33BAA6F65CDD928319D7065E040E7A5E84F9AA903F7648094BAD07136B16927B8EC"
          + "6DBC2BEF0CC2856DE1E795923E1412C49F24DEEB6C21F6C8A9765C9C7986E0DA4B4C67D8E0D0C8D466824"
          + "FB923D8573148990CD2EF133C78CEECAB72ED9DD285C5A3766852D54534207FFD34027F6C76EDE8FD1A32"
          + "D72C30048BBAA797D5DF6FDE27D087DE5721AD7B7FA3E8D3F70D6BFC3AB2E252335368BBFA15ACB5CB37D"
          + "4694E8B23CEBE25DE9C925A221A183B904D3F85DF9929A919C54D6F87457373A0D6ECC1403E4CBBE62099"
          + "9435E80696634CD1A8E4747E9825BFA336E5BBAD14F73640F1B9FEBE800DBAEFE1630C61FAE635B074C56"
          + "4EAA9DB189C9E7302873FC64E6D497BC5C29080987A07A21D4AF210703A4FA07F2FD816F12FD1E29B4C0F"
          + "44AFE9BD4A1EAA8A7AE6F02A5B4258F52CAF6127F62632A67CF4E8310BE56A7C28C86B2E277600C3E92C8"
          + "D23D42586244C571E90568DF202F2F6D81F860A565F9EB91A3C78372E2A8B1BE61C5418CF49BF2D6C8955"
          + "D4A482A9919B7660B3F9A4404FFC454EA073E1E4B2689AB2CCA4E46BD7004A6C491FA26EE7A57D60F35ED"
          + "B2B821E6266442C8F335D452D524C772E0353724C23C7DD15B7AA155E91442022140C5FCB0153147EDCF3"
          + "E8952F6F0399A3C88066A72756C9409915DE63F64FA797841C57C796C6FC550EF745DFE9F179457F94755"
          + "AE5A2506A764F327E550BE3DC14DD41F3B04B147D454938C63A8D69B2EA4C5710EC0B36E3A6C72571FA5D"
          + "59DDE036C42033DF35AF056966FF0CD1204008971AA6BA9FB97B685AB9FFA2A9D1778104CD2C3B326DE1F"
          + "CBC242E94D0311C3275B12850ED30CEEAD3A2EE6D060508411D4396F5421D8B6D067CF7CB5E826785FBE1"
          + "19E05E21BD879B64F57CB0CD1972C2815F20ABE7CE6AB34D0F471AF44BAAD179E90644122F5F33288E689"
          + "DDDDC5CE833E9755DF1E73C65C5A201C4EDE2FFA6B19274927719D2D38FDB7A65AA43708B7FA9A94AA7D3"
          + "210253D78D3B181E1020D0000BD0A1DC05D447F9F58EBEB84C65B36C8AFCB83727A1508994E826957A663"
          + "B0B9B8A003325AB6D6D6462EE4E106019C0DFFE10323B7BDE7D82A38F85FD08786E860BA66C161B64B070"
          + "8C363DE5C6AF62D8DB3C243D1E1B712CB1D59E942B9B6B4295A5A500B182CBD5FD1BC6CE9376D91B47A22"
          + "84F1FBE0AD1C048CC2CFBB4AFA3A9EB9697503B69FECA990EBA7E9441AF9CA44CB3AC6B5ED66E591C201F"
          + "E30EFA8A7C471DC613D6254C263A8E132104BEC47F1AACB3B2FCD4051B69B5E3FCB1C147A65C2F90C4B51"
          + "88BAFC521CAB03C12A309DA50B5A7517727ED41228ED123FE1B152F6A6319CD623BF34AD7B8E064AB9932"
          + "60BCBD405F5B7FFF9B2FA40BA5ED5630242539E5D96823E89DC818A13D16675EE3079D976F694F5ACC976"
          + "0AE789E9B3391B289E0E22A7EF17CC6A4577157B6D95C09BAA4FD532E3EE0A290810ED35E56BB19D9B61F"
          + "B98A97C617425B06093D98A5CF0EE2DD127F0EEA600B9A0C67FBE761DB9B77E5D5BBA9701DA1B883E521A"
          + "0CFE88451F57BD36085B67E56F061F84A2E6A152A71BCE6E522DAAB6A0A33CE22E537FA9793D28B617E6C"
          + "0A4176A83AA3BE578AFAC0F2F5547C5516D218984755B7445C7143AFA4E551FCE0071BDB873B34E6B9E2B"
          + "9E79ED0C69D288ED6421F237E860A0C6492EBBDD2A44C2C4F368DBE99941B1E8561D859D3859F496CEE3D"
          + "741F252973F8FCC539C409E35CC80A5ED6DF23CC3A65601313F5D681FD9540C5291A9E30A72E38C96413C"
          + "47C61FF84FDE78D011B01B4154D1B920AF003F7ABB1E1999DEA6A766CF9FD2702B3CE0EE57AF931B62124"
          + "B0861B163A3B91AA4BEA28076C3432DF3B29B6C4E1BA588DEF420071FC157DE90EB2722ECC9AB00DF3C66"
          + "9383A61A91BB67BD287CE349B4745EE7A479DBCEEF166B9ACC412EB579FCD6437307EDDA253D606B7BE75"
          + "99C38092BC52A8598480EDAB8B82B1D21C565D2137CEAE0B6642619B16133D91205D6355029E9CDFEB9A2"
          + "8B373D95916B6B707D4C712C09CF36DAF1A511B2BEDB1AA70EE58D46A0666BB287784B0A3840C589A7A04"
          + "D5D6F2216BE90AA4A512D5632F5C9BFE7B8B13382F999B95D367C7C46B968074CE315197A5FF3545C7B77"
          + "A804ADE56A95B5C24CDECE5937B5C0366D93AD03DA9BC5DB1B551DFB91E9B343D2B57B763439686D4A321"
          + "58200000000000000000000000000000000000000000000000000000000000000000";

  private static final byte[] pubBytes = new byte[1952]; // ML-DSA-65 public key length
  private static final byte[] privBytes = new byte[32]; // ML-DSA-65 seed length
  private static final String PROVIDER;

  static {
    for (int i = 0; i < pubBytes.length; i++) {
      pubBytes[i] = (byte) (i % 256);
    }
    for (int i = 0; i < privBytes.length; i++) {
      privBytes[i] = (byte) ((31 - i) % 256);
    }

    Provider conscrypt = Conscrypt.newProvider();
    if (Security.getProvider(conscrypt.getName()) == null) {
      Security.addProvider(conscrypt);
    }
    PROVIDER = conscrypt.getName();
  }

  @Test
  public void testRoundTrip() throws CborException, CoseException {
    final byte[] keyId = TestUtilities.KEYID_BYTES;
    final Map map = new Map();
    map.put(
        new UnsignedInteger(Headers.KEY_PARAMETER_KEY_TYPE),
        new UnsignedInteger(Headers.KEY_TYPE_AKP));
    map.put(new UnsignedInteger(Headers.KEY_PARAMETER_KEY_ID), new ByteString(keyId));
    map.put(
        new UnsignedInteger(Headers.KEY_PARAMETER_ALGORITHM),
        Algorithm.SIGNING_ALGORITHM_MLDSA_65.getCoseAlgorithmId());
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_AKP_PUB), new ByteString(pubBytes));
    map.put(new NegativeInteger(Headers.KEY_PARAMETER_AKP_PRIV), new ByteString(privBytes));

    final AkpSigningKey key = new AkpSigningKey(map);
    byte[] serialized = key.serialize();

    final AkpSigningKey parsedKey = AkpSigningKey.parse(serialized);

    assertThat(parsedKey).isNotNull();

    assertThat(parsedKey.getKeyType()).isEqualTo(Headers.KEY_TYPE_AKP);
    assertArrayEquals(keyId, parsedKey.getKeyId());
    assertThat(parsedKey).isEqualTo(key);
  }

  @Test
  public void testParseKeyFailureWrongKeyType() throws CborException, CoseException {
    final String cborString =
        "A4010220012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
            + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    CoseException exception =
        assertThrows(
            CoseException.class,
            () -> AkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString)));
    assertThat(exception).hasMessageThat().startsWith("Expecting KEY_TYPE_AKP");
  }

  @Test
  public void testParseKeyFailureMissingAlgorithm() throws CborException, CoseException {
    final String cborString =
        "A4010720012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
            + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    CoseException exception =
        assertThrows(
            CoseException.class,
            () -> AkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString)));
    assertThat(exception).hasMessageThat().isEqualTo("Algorithm is required for AKP keys.");
  }

  @Test
  public void testParseKeyFailureOkpKeyAsAkpKey() throws CborException, CoseException {
    // OKP Keys have a different public key structure.
    final String cborString =
        "A5010703382F20012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
            + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    CborException exception =
        assertThrows(
            CborException.class,
            () -> AkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString)));
    assertThat(exception).hasMessageThat().startsWith("Expected a byte string");
  }

  @Test
  public void testParseKeyFailureUnsupportedAlgorithm() throws CborException, CoseException {
    final String cborString =
        "A50107032720012158205A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA44"
            + "4B624343167FE225820B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67";
    CoseException exception =
        assertThrows(
            CoseException.class,
            () -> AkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString)));
    assertThat(exception).hasMessageThat().startsWith("Expecting an AKP signing");
  }

  @Test
  public void testParseKeyFailureMissingKeyMaterial() throws CborException, CoseException {
    final String cborString = "A20107033830";
    CoseException exception =
        assertThrows(
            CoseException.class,
            () -> AkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString)));
    assertThat(exception).hasMessageThat().startsWith("Missing key material");
  }

  @Test
  public void testEmptyPrivateKeyBytes() throws CborException, CoseException {
    final String cborString = "A301070338302140";
    CoseException exception =
        assertThrows(
            CoseException.class,
            () -> AkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString)));
    assertThat(exception)
        .hasMessageThat()
        .isEqualTo("Could not decode private key. Expected key material.");
  }

  @Test
  public void testEmptyPublicKeyBytes() throws CborException, CoseException {
    final String cborString = "A301070338302040";
    CoseException exception =
        assertThrows(
            CoseException.class,
            () -> AkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString)));
    assertThat(exception)
        .hasMessageThat()
        .isEqualTo("Could not decode public key. Expected key material.");
  }

  @Test
  public void testParseKeyFailureWrongKeyOperation() throws CborException, CoseException {
    final String cborString =
        "A401070338302158200000000000000000000000000000000000000000000000000000000000000000"
            + "04820304";
    CoseException exception =
        assertThrows(
            CoseException.class,
            () -> AkpSigningKey.parse(TestUtilities.hexStringToByteArray(cborString)));
    assertThat(exception)
        .hasMessageThat()
        .startsWith("Signing key requires either sign or verify operation.");
  }

  @Test
  public void testParseKeySuccess() throws CborException, CoseException {
    AkpSigningKey key =
        AkpSigningKey.parse(TestUtilities.hexStringToByteArray(COSE_ENCODED_MLDSA87_KEY));
    assertThat(key).isNotNull();
    assertThat(key.getKeyType()).isEqualTo(Headers.KEY_TYPE_AKP);
    assertThat(key.getAlgorithm())
        .isEqualTo(CborUtils.asInteger(Algorithm.SIGNING_ALGORITHM_MLDSA_87.getCoseAlgorithmId()));
    assertThat(key.getPublicKeyBytes()).isNotNull();
    assertThat(TestUtilities.bytesToHexString(key.serialize())).isEqualTo(COSE_ENCODED_MLDSA87_KEY);
  }

  @Test
  public void testBuilder() throws CborException, CoseException {
    AkpSigningKey signingKey =
        AkpSigningKey.builder()
            .withAlgorithm(Algorithm.SIGNING_ALGORITHM_MLDSA_65)
            .withPublicKey(pubBytes)
            .withPrivateKey(privBytes)
            .build();

    assertThat(signingKey.getKeyType()).isEqualTo(Headers.KEY_TYPE_AKP);
    assertArrayEquals(pubBytes, signingKey.getPublicKeyBytes());
    Map map = CborUtils.asMap(signingKey.encode());
    assertThat(map.get(new UnsignedInteger(Headers.KEY_PARAMETER_ALGORITHM)))
        .isEqualTo(Algorithm.SIGNING_ALGORITHM_MLDSA_65.getCoseAlgorithmId());
    assertThat(map.get(new NegativeInteger(Headers.KEY_PARAMETER_AKP_PUB)))
        .isEqualTo(new ByteString(pubBytes));
    assertThat(map.get(new NegativeInteger(Headers.KEY_PARAMETER_AKP_PRIV)))
        .isEqualTo(new ByteString(privBytes));
  }

  @Test
  public void testBuilderFailureMissingAlgorithm() {
    AkpSigningKey.Builder builder =
        AkpSigningKey.builder().withPublicKey(pubBytes).withPrivateKey(privBytes);
    assertThrows(CoseException.class, builder::build);
  }

  @Test
  public void testBuilderFailureMissingKeyMaterial() {
    AkpSigningKey.Builder builder =
        AkpSigningKey.builder().withAlgorithm(Algorithm.SIGNING_ALGORITHM_MLDSA_65);
    CoseException exception = assertThrows(CoseException.class, builder::build);
    assertThat(exception).hasMessageThat().startsWith("Missing key material");
  }

  @Test
  public void testBuilderFailureWrongOperation() {
    AkpSigningKey.Builder builder =
        AkpSigningKey.builder()
            .withAlgorithm(Algorithm.SIGNING_ALGORITHM_MLDSA_65)
            .withPublicKey(pubBytes);
    assertThrows(CoseException.class, () -> builder.withOperations(Headers.KEY_OPERATIONS_ENCRYPT));
  }

  @Test
  public void testBuilderSuccessOnlyPrivateKey() throws CborException, CoseException {
    AkpSigningKey signingKey =
        AkpSigningKey.builder()
            .withAlgorithm(Algorithm.SIGNING_ALGORITHM_MLDSA_65)
            .withPrivateKey(privBytes)
            .build();
    assertThat(signingKey.getKeyType()).isEqualTo(Headers.KEY_TYPE_AKP);
    assertThat(signingKey.getAlgorithm())
        .isEqualTo(CborUtils.asInteger(Algorithm.SIGNING_ALGORITHM_MLDSA_65.getCoseAlgorithmId()));
  }

  @Test
  public void testBuilderFailureWrongKeyOperation() {
    AkpSigningKey.Builder builder =
        AkpSigningKey.builder()
            .withAlgorithm(Algorithm.SIGNING_ALGORITHM_MLDSA_65)
            .withPrivateKey(privBytes);
    assertThrows(CoseException.class, () -> builder.withOperations(Headers.KEY_OPERATIONS_ENCRYPT));
  }

  @Test
  public void testBuilderSuccess() throws CborException, CoseException {
    AkpSigningKey signingKey =
        AkpSigningKey.builder()
            .withAlgorithm(Algorithm.SIGNING_ALGORITHM_MLDSA_65)
            .withPublicKey(pubBytes)
            .withOperations(Headers.KEY_OPERATIONS_SIGN, Headers.KEY_OPERATIONS_VERIFY)
            .build();
    assertThat(signingKey.getKeyType()).isEqualTo(Headers.KEY_TYPE_AKP);
    assertThat(signingKey.getAlgorithm())
        .isEqualTo(CborUtils.asInteger(Algorithm.SIGNING_ALGORITHM_MLDSA_65.getCoseAlgorithmId()));
    signingKey.verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_SIGN);
    signingKey.verifyOperationAllowedByKey(Headers.KEY_OPERATIONS_VERIFY);
  }

  @Test
  public void testGenerateKeyMLDSA65() throws CborException, CoseException {
    AkpSigningKey key = AkpSigningKey.generateKey(Algorithm.SIGNING_ALGORITHM_MLDSA_65, PROVIDER);
    assertThat(key).isNotNull();
    assertThat(key.getKeyType()).isEqualTo(Headers.KEY_TYPE_AKP);
    assertThat(key.getAlgorithm())
        .isEqualTo(CborUtils.asInteger(Algorithm.SIGNING_ALGORITHM_MLDSA_65.getCoseAlgorithmId()));
    assertThat(key.getPublicKeyBytes()).isNotNull();
    assertThat(key.getPublicKeyBytes()).hasLength(1952);
  }

  @Test
  public void testGenerateKeyMLDSA87() throws CborException, CoseException {
    AkpSigningKey key = AkpSigningKey.generateKey(Algorithm.SIGNING_ALGORITHM_MLDSA_87, PROVIDER);
    assertThat(key).isNotNull();
    assertThat(key.getKeyType()).isEqualTo(Headers.KEY_TYPE_AKP);
    assertThat(key.getAlgorithm())
        .isEqualTo(CborUtils.asInteger(Algorithm.SIGNING_ALGORITHM_MLDSA_87.getCoseAlgorithmId()));
  }

  @Test
  public void testGenerateKeyFailureUnsupportedAlgorithm() {
    assertThrows(
        CoseException.class,
        () -> AkpSigningKey.generateKey(Algorithm.SIGNING_ALGORITHM_EDDSA, PROVIDER));
  }

  @Test
  public void testSignAndVerifyMLDSA65() throws CborException, CoseException {
    AkpSigningKey signingKey =
        AkpSigningKey.generateKey(Algorithm.SIGNING_ALGORITHM_MLDSA_65, PROVIDER);
    byte[] message = TestUtilities.CONTENT_BYTES;
    byte[] signature = signingKey.sign(Algorithm.SIGNING_ALGORITHM_MLDSA_65, message, PROVIDER);

    signingKey.verify(Algorithm.SIGNING_ALGORITHM_MLDSA_65, message, signature, PROVIDER);
  }

  @Test
  public void testSignAndVerifyMLDSA87() throws CborException, CoseException {
    AkpSigningKey signingKey =
        AkpSigningKey.generateKey(Algorithm.SIGNING_ALGORITHM_MLDSA_87, PROVIDER);
    byte[] message = TestUtilities.CONTENT_BYTES;
    byte[] signature = signingKey.sign(Algorithm.SIGNING_ALGORITHM_MLDSA_87, message, PROVIDER);

    signingKey.verify(Algorithm.SIGNING_ALGORITHM_MLDSA_87, message, signature, PROVIDER);
  }

  @Test
  public void testSignAndVerifyFailureWrongAlgorithm() throws CborException, CoseException {
    AkpSigningKey signingKey =
        AkpSigningKey.generateKey(Algorithm.SIGNING_ALGORITHM_MLDSA_65, PROVIDER);
    byte[] message = TestUtilities.CONTENT_BYTES;
    byte[] signature = signingKey.sign(Algorithm.SIGNING_ALGORITHM_MLDSA_65, message, PROVIDER);
    assertThrows(
        CoseException.class,
        () ->
            signingKey.verify(Algorithm.SIGNING_ALGORITHM_MLDSA_87, message, signature, PROVIDER));
  }

  @Test
  public void testSignAndVerifyWithExplicitProvider() throws CborException, CoseException {
    byte[] message = TestUtilities.CONTENT_BYTES;
    AkpSigningKey key = AkpSigningKey.generateKey(Algorithm.SIGNING_ALGORITHM_MLDSA_65, PROVIDER);

    String provider = AkpKey.CONSCRYPT_PROVIDER;
    byte[] signature = key.sign(Algorithm.SIGNING_ALGORITHM_MLDSA_65, message, provider);
    assertThat(signature).isNotNull();

    key.verify(Algorithm.SIGNING_ALGORITHM_MLDSA_65, message, signature, provider);
  }

  @Test
  public void testSignAndVerifyFailureNullProvider() throws CborException, CoseException {
    byte[] message = TestUtilities.CONTENT_BYTES;
    Algorithm algorithm = Algorithm.SIGNING_ALGORITHM_MLDSA_65;
    AkpSigningKey key = AkpSigningKey.generateKey(algorithm, PROVIDER);
    assertThrows(IllegalArgumentException.class, () -> key.sign(algorithm, message, null));

    String provider = AkpKey.CONSCRYPT_PROVIDER;
    byte[] signature = key.sign(algorithm, message, provider);
    assertThrows(
        IllegalArgumentException.class, () -> key.verify(algorithm, message, signature, null));
  }
}
