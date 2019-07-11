package org.springframework.vault.authentication;

import java.util.function.Supplier;

@FunctionalInterface
public interface CloudFoundryInstanceCredentialSupplier extends Supplier<String> {

	/**
	 * Get instance credentials for CloudFoundry authentication.
	 *
	 * @return the CloudFoundry instance credentials (certificate or private key)
	 */
	@Override
	String get();
}
