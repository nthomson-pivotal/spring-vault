package org.springframework.vault.authentication;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.vault.VaultException;
import org.springframework.vault.support.VaultResponse;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;

public class CloudFoundryAuthentication implements ClientAuthentication {

	private static final Log logger = LogFactory.getLog(CloudFoundryAuthentication.class);
	
	private static final DateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");

	private final CloudFoundryAuthenticationOptions options;

	private final RestOperations restOperations;

	public CloudFoundryAuthentication(CloudFoundryAuthenticationOptions options, 
			RestOperations restOperations) {
		this.options = options;
		this.restOperations = restOperations;
	}

	@Override
	public VaultToken login() {
		Map<String, String> login = new HashMap<String, String>();

		String role = options.getRole();
		String certificate = options.getCertificateSupplier().get();
		
		PrivateKey key = createKey(options.getKeySupplier().get());

		String timeSigned = dateFormatter.format(new Date());
		
		String signature = sign(Sha256.toSha256(timeSigned +
				certificate +
				role), key);
		
		login.put("role", role);
		login.put("signing_time", timeSigned);
		login.put("signature", signature);
		login.put("cf_instance_cert", certificate);

		try {
			VaultResponse response = restOperations.postForObject("auth/{mount}/login", 
					login, VaultResponse.class, options.getPath());

			logger.debug("Login successful using CloudFoundry authentication");

			return LoginTokenUtil.from(response.getAuth());
		} catch (RestClientException e) {
			throw VaultLoginException.create("CloudFoundry", e);
		}
	}
	
	private static String sign(String checksum, PrivateKey key) throws VaultException {
		try {
			Signature signature = Signature.getInstance("SHA256withRSA/PSS");
			signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
			signature.initSign(key);
	        signature.update(checksum.getBytes());
	        
	        String encoded = java.util.Base64.getEncoder().encodeToString(signature.sign());
	        
	        return encoded.replace('+', '-').replace('/', '_');
        }
		catch(Exception e) {
			throw new VaultException("Failed to sign checksum", e);
		}
	}
	
	private static PrivateKey createKey(String contents) {
		PrivateKey key;
		
		try (PEMParser pemParser = new PEMParser(new StringReader(contents))) {
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			Object object = pemParser.readObject();
			KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
			key = kp.getPrivate();
		}
		catch(Exception e) {
			throw new VaultException("Failed to load private key", e);
		}
		
		return key;
	}
}
