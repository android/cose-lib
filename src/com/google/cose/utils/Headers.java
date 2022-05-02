package com.google.cose.utils;

/**
 * This class contains all the header keys that we are going to be using in COSE implementation.
 */
public class Headers {
  public static final int KEY_PARAMETER_KEY_TYPE = 1;
  public static final int KEY_PARAMETER_KEY_ID = 2;
  public static final int KEY_PARAMETER_ALGORITHM = 3;
  public static final int KEY_PARAMETER_OPERATIONS = 4;
  public static final int KEY_PARAMETER_BASE_IV = 5;

  public static final int KEY_TYPE_RESERVED = 0;
  public static final int KEY_TYPE_OKP = 1;
  public static final int KEY_TYPE_ECC = 2;
  public static final int KEY_TYPE_SYMMETRIC = 4;

  public static final int KEY_OPERATIONS_SIGN = 1;
  public static final int KEY_OPERATIONS_VERIFY = 2;
  public static final int KEY_OPERATIONS_ENCRYPT = 3;
  public static final int KEY_OPERATIONS_DECRYPT = 4;
  public static final int KEY_OPERATIONS_MAC_CREATE = 9;
  public static final int KEY_OPERATIONS_MAC_VERIFY = 10;

  public static final int MESSAGE_HEADER_ALGORITHM = 1;
  public static final int MESSAGE_HEADER_CRITICALITY = 2;
  public static final int MESSAGE_HEADER_CONTENT_TYPE = 3;
  public static final int MESSAGE_HEADER_KEY_ID = 4;
  public static final int MESSAGE_HEADER_BASE_IV = 5;
  public static final int MESSAGE_HEADER_PARTIAL_IV = 6;
  public static final int MESSAGE_HEADER_COUNTER_SIGNATURE = 7;

  public static final int KEY_PARAMETER_CURVE = -1;
  public static final int KEY_PARAMETER_X = -2;
  public static final int KEY_PARAMETER_Y = -3;
  public static final int KEY_PARAMETER_D = -4;

  public static final int KEY_PARAMETER_K = -1;

  public static final int CURVE_EC2_P256 = 1;
  public static final int CURVE_EC2_P384 = 2;
  public static final int CURVE_EC2_P521 = 3;

  public static final int CURVE_OKP_X25519 = 4;
  public static final int CURVE_OKP_X448 = 5;
  public static final int CURVE_OKP_Ed25519 = 6;
  public static final int CURVE_OKP_Ed448 = 7;
}
