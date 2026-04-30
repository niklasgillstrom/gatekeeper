package eu.gillstrom.gatekeeper.verification;

import eu.gillstrom.gatekeeper.model.HsmVendor;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public interface HsmAttestationVerifier {
    
    HsmVendor getVendor();
    
    boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey);
    
    boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain);
    
    String extractSerialNumber(X509Certificate attestationCert);
    
    String extractModel(X509Certificate attestationCert);
}
