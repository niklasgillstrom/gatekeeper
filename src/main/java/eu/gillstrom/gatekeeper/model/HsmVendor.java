package eu.gillstrom.gatekeeper.model;

/**
 * Supported HSM vendors for key attestation verification.
 * 
 * Each vendor has different attestation mechanisms:
 * - YUBICO: Certificate-based attestation with device certificate chain
 * - SECUROSYS: XML attestation with signature and certificate chain
 * - AZURE: JSON attestation from Azure Managed HSM (Marvell hardware)
 * - GOOGLE: Binary attestation blob with certificate chain
 * - MARVELL: Binary attestation blob from a physical LiquidSecurity HSM with its partition and card certificates
 * - THALES: Luna Public Key Confirmation (PKCS#7 certificate chain)
 * - CRYPTO4A: QASM attestation message (signed claims)
 * - FORTANIX: DSM key attestation statement (JSON with X.509 statement)
 * - ENTRUST: nShield key attestation bundle (JSON: warrant, module state, key generation certificate)
 */
public enum HsmVendor {
    YUBICO("Yubico", "YubiHSM 2"),
    SECUROSYS("Securosys", "Primus HSM"),
    AZURE("Microsoft", "Azure Key Vault HSM"),
    GOOGLE("Google Cloud", "Cloud HSM"),
    MARVELL("Marvell", "LiquidSecurity HSM"),
    THALES("Thales", "Luna HSM"),
    CRYPTO4A("Crypto4A", "QASM"),
    FORTANIX("Fortanix", "DSM"),
    ENTRUST("Entrust", "nShield");
    
    private final String vendorName;
    private final String productName;
    
    HsmVendor(String vendorName, String productName) {
        this.vendorName = vendorName;
        this.productName = productName;
    }
    
    public String getVendorName() { return vendorName; }
    public String getProductName() { return productName; }
}
