package org.springframework.vault.authentication;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.StreamUtils;
import org.springframework.vault.VaultException;

public class CloudFoundryInstanceCredentialsFile implements CloudFoundryInstanceCredentialSupplier {

	/**
	 * Default path to the instance credentials file.
	 */
	public static final String DEFAULT_CF_INSTANCE_CREDENTIALS_DIR = "/etc/cf-instance-credentials/";

	private byte[] contents;

	public CloudFoundryInstanceCredentialsFile(String path) {
        this(new FileSystemResource(path));
    }

	public CloudFoundryInstanceCredentialsFile(File file) {
        this(new FileSystemResource(file));
    }
	
	public static CloudFoundryInstanceCredentialsFile certificate() {
		return new CloudFoundryInstanceCredentialsFile(DEFAULT_CF_INSTANCE_CREDENTIALS_DIR+"instance.crt");
	}
	
	public static CloudFoundryInstanceCredentialsFile key() {
		return new CloudFoundryInstanceCredentialsFile(DEFAULT_CF_INSTANCE_CREDENTIALS_DIR+"instance.key");
	}

	public CloudFoundryInstanceCredentialsFile(Resource resource) {

		Assert.isTrue(resource.exists(),
				() -> String.format("Resource %s does not exist", resource));

		try {
			this.contents = readContents(resource);
		}
		catch (IOException e) {
			throw new VaultException(String.format(
					"CF instance credential retrieval from %s failed", resource), e);
		}
	}

	@Override
	public String get() {
		return new String(contents, StandardCharsets.US_ASCII);
	}

	protected static byte[] readContents(Resource resource) throws IOException {

		Assert.notNull(resource, "Resource must not be null");

		try (InputStream is = resource.getInputStream()) {
			return StreamUtils.copyToByteArray(is);
		}
	}
}