import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class VerifyXMLERS {

    private String signedFilePath;
    private CommonCertificateVerifier certificateVerifier;

    // Constructor to initialize the verifier
    public VerifyXMLERS(String signedFilePath) {
        this.signedFilePath = signedFilePath;
        this.certificateVerifier = new CommonCertificateVerifier(); // Default verifier
    }

    // Constructor with custom certificate verifier
    public VerifyXMLERS(String signedFilePath, CommonCertificateVerifier customVerifier) {
        this.signedFilePath = signedFilePath;
        this.certificateVerifier = customVerifier;
    }

    public VerifyXMLERS() {

    }

    // Method to perform verification
    public void verifySignature(String outputXmlPath) {
        try {
            // Load the signed XML document
            DSSDocument signedDocument = new FileDocument(signedFilePath);

            // Initialize the validator for XAdES
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
            validator.setCertificateVerifier(certificateVerifier);

            // Generate the reports (validation, diagnostic, and simple report)
            Reports reports = validator.validateDocument();

            // Print validation result
            System.out.println(reports.getXmlSimpleReport());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}