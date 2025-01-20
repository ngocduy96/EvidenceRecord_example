import eu.europa.esig.dss.model.*;
import vn.mobileid.services.pades.PAdES;
import vn.mobileid.services.xades.XAdES;

public class ERSTest {
    private static final String inputPdfPath = "src/test/java/files/input.pdf";
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
        XAdES xadesService = new XAdES(p12FilePath, p12Password, TSA_URL);
        DSSDocument xAdESDocument = xadesService.signXAdESDocument(new FileDocument(inputXMLpath));
        xAdESDocument.save(outputXMLpath);

        PAdES padesService = new PAdES(p12FilePath, p12Password, TSA_URL);
        DSSDocument pAdESDocument = padesService.signPAdESDocument(new FileDocument(inputPdfPath));
        pAdESDocument.save(outputPdfPath1);

        DSSDocument pdfTimestampedDocument = padesService.pdfTimestamping(pAdESDocument);
        pdfTimestampedDocument.save(outputPdfPath2);

    }


}