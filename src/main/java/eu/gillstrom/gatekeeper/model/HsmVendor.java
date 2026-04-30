package eu.gillstrom.gatekeeper.model;

/**
 * Supported HSM vendors for key attestation verification.
 * 
 * Each vendor has different attestation mechanisms:
 * - YUBICO: Certificate-based attestation with device certificate chain
 * - SECUROSYS: XML attestation with signature and certificate chain
 * - AZURE: JSON attestation from Azure Managed HSM (Marvell hardware)
 * - GOOGLE: Binary attestation blob with certificate chain
 */
public enum HsmVendor {
    YUBICO("Yubico", "YubiHSM 2"),
    SECUROSYS("Securosys", "Primus HSM"),
    AZURE("Microsoft", "Azure Key Vault HSM"),
    GOOGLE("Google Cloud", "Cloud HSM");
    
    private final String vendorName;
    private final String productName;
    
    HsmVendor(String vendorName, String productName) {
        this.vendorName = vendorName;
        this.productName = productName;
    }
    
    public String getVendorName() { return vendorName; }
    public String getProductName() { return productName; }
}
