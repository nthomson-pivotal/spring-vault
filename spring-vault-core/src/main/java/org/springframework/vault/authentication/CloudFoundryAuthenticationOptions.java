package org.springframework.vault.authentication;

import java.util.function.Supplier;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

public class CloudFoundryAuthenticationOptions {

	public static final String DEFAULT_CF_AUTHENTICATION_PATH = "cf";

	/**
	 * Path of the CF authentication backend mount.
	 */
	private final String path;

	/**
	 * Supplier instance to obtain a CloudFoundry instance credentials certificate
	 */
    private final Supplier<String> certificateSupplier;
    
    /**
	 * Supplier instance to obtain a CloudFoundry instance credentials key
	 */
    private final Supplier<String> keySupplier;
    
    /**
	 * Name of the role against which the login is being attempted.
	 */
	private final String role;

	private CloudFoundryAuthenticationOptions(String path, String role, 
			Supplier<String> certificateSupplier, Supplier<String> keySupplier) {

		this.path = path;
		this.role = role;
        this.certificateSupplier = certificateSupplier;
        this.keySupplier = keySupplier;
	}

	public static CloudFoundryAuthenticationOptionsBuilder builder() {
		return new CloudFoundryAuthenticationOptionsBuilder();
	}

	/**
	 * @return the path of the CF authentication backend mount.
	 */
	public String getPath() {
		return path;
	}
	
	/**
	 * @return name of the role against which the login is being attempted.
	 */
	public String getRole() {
		return role;
	}

	public Supplier<String> getCertificateSupplier() {
		return certificateSupplier;
	}

    public Supplier<String> getKeySupplier() {
		return keySupplier;
	}

	public static class CloudFoundryAuthenticationOptionsBuilder {

		private String path = DEFAULT_CF_AUTHENTICATION_PATH;
		
		@Nullable
		private String role;

        private Supplier<String> certificateSupplier;

        private Supplier<String> keySupplier;
		
		/**
		 * Configure the mount path.
		 *
		 * @param path must not be {@literal null} or empty.
		 * @return {@code this} {@link CloudFoundryAuthenticationOptionsBuilder}.
		 */
		public CloudFoundryAuthenticationOptionsBuilder path(String path) {

			Assert.hasText(path, "Path must not be empty");

			this.path = path;
			return this;
		}
		
		/**
		 * Configure the role.
		 *
		 * @param role name of the role against which the login is being attempted, must
		 * not be {@literal null} or empty.
		 * @return {@code this} {@link CloudFoundryAuthenticationOptionsBuilder}.
		 */
		public CloudFoundryAuthenticationOptionsBuilder role(String role) {

			Assert.hasText(role, "Role must not be empty");

			this.role = role;
			return this;
		}
        
		public CloudFoundryAuthenticationOptionsBuilder certificateSupplier(
				Supplier<String> certificateSupplier) {
			this.certificateSupplier = certificateSupplier;
			return this;
        }
        
        public CloudFoundryAuthenticationOptionsBuilder keySupplier(
				Supplier<String> keySupplier) {
			this.keySupplier = keySupplier;
			return this;
		}

		public CloudFoundryAuthenticationOptions build() {
			return new CloudFoundryAuthenticationOptions(path, role, 
					certificateSupplier == null ? CloudFoundryInstanceCredentialsFile.certificate()
                            : certificateSupplier,
                    keySupplier == null ? CloudFoundryInstanceCredentialsFile.key()
							: keySupplier);
		}
	}
}
