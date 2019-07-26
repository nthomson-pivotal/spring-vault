package org.springframework.vault.authentication;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.springframework.vault.VaultException;
import org.springframework.vault.support.VaultResponse;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;

public class CloudFoundryAuthentication implements ClientAuthentication {

	private static final Log logger = LogFactory.getLog(CloudFoundryAuthentication.class);

	private final CloudFoundryAuthenticationOptions options;

	private final RestOperations restOperations;

	public CloudFoundryAuthentication(CloudFoundryAuthenticationOptions options, RestOperations restOperations) {
		this.options = options;
		this.restOperations = restOperations;
	}

	@Override
	public VaultToken login() {
		String role = options.getRole();
		String certificate = options.getCertificateSupplier().get();

		PrivateKey privateKey = createPrivateKey(options.getKeySupplier().get());
		
		DateTimeFormatter fmt = ISODateTimeFormat.dateTimeNoMillis();
		String signingTimeStr = fmt.print(DateTime.now().withZone(DateTimeZone.UTC));

		String payload = signingTimeStr.trim() + certificate.trim() + role.trim();
		System.out.println(payload);

		try {
			Map<String, String> login = new LinkedHashMap<String, String>();
			login.put("role", role.trim());
			login.put("signing_time", signingTimeStr.trim());
			login.put("cf_instance_cert", certificate.trim());
			login.put("signature", sign(payload.getBytes(), privateKey).trim());

			VaultResponse response = restOperations.postForObject("auth/{mount}/login", login, VaultResponse.class,
					options.getPath());

			logger.debug("Login successful using CloudFoundry authentication");

			return LoginTokenUtil.from(response.getAuth());
		} catch (RestClientException e) {
			throw VaultLoginException.create("CloudFoundry", e);
		}
	}

	private static String sign(byte[] data, PrivateKey key) throws VaultException {
		try {

			Signature signature = Signature.getInstance("RSASSA-PSS", "BC");
			signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 222,
					PSSParameterSpec.DEFAULT.getTrailerField()));
			signature.initSign(key);
			signature.update(data);
			byte[] sig = signature.sign();

			return java.util.Base64.getUrlEncoder().encodeToString(sig);
		} catch (Exception e) {
			throw new VaultException("Failed to sign checksum", e);
		}
	}

	private static PrivateKey createPrivateKey(String contents) {
		PrivateKey key;

		try (PEMParser pemParser = new PEMParser(new StringReader(contents))) {
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			Object object = pemParser.readObject();
			KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
			key = kp.getPrivate();
		} catch (Exception e) {
			throw new VaultException("Failed to load private key", e);
		}

		return key;
	}
}