package com.google.cose.exceptions;

/**
 * This class is used for throwing any exceptions that may occur during parsing and serialization of
 * byte data into their respective COSE components.
 */
public class CoseException extends RuntimeException {
  public CoseException(final String message) {
    super(message);
  }

  public CoseException(final String message, final Exception ex) {
    super(message, ex);
  }
}
