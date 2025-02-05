import vn.mobile.id.config.SignerConfig;
import vn.mobile.id.services.pades.PAdES;

public class ERSTest {
    private static final String inputPdfPath = "src/test/java/files/input.pdf";
    private static final String inputImagePath = "src/test/java/files/logo.jpg";
    private static final String inputCMSPath = "src/test/java/files/input.docx";
    private static final String outputCMSPath = "src/test/java/files/output.docx";
    private static final String outputPdfPath1 = "src/test/java/files/output_with_evidence_record-1.pdf";
    private static final String outputPdfPath2 = "src/test/java/files/timestampedPDF.pdf";
    private static final String outputReportPath = "src/test/java/files/report.xml";
    private static final String inputXMLpath = "src/test/java/files/input.xml";
    private static final String outputXMLpath = "src/test/java/files/output.xml";
    private static final String outputERSPath = "src/test/java/files/evidence_record.ers";
    private static final String tsrPath = "src/test/java/files/input.tsr";
    private static final String tspPath = "src/test/java/files/input.tsp";
    private static final String p12FilePath = "src/test/java/files/duynguyen.p12";
    private static final String p12Password = "12345678";
    private static final String TSA_URL = "http://ca.gov.vn/tsa";

    public static void main(String[] args) throws Exception {
        SignerConfig config = new SignerConfig(p12FilePath, p12Password, TSA_URL);

        PAdES padesService = new PAdES(config);
        padesService.signDocument(inputPdfPath);
        padesService.timestampDocument(inputPdfPath);
        padesService.extendLTA(inputPdfPath);
    }


}