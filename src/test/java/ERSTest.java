import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecordAnalyzer;
import eu.europa.esig.dss.model.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import vn.mobileid.core.EvidenceRecord;
import vn.mobileid.services.xades.XAdESService;
import vn.mobileid.services.pades.PAdESService;
import vn.mobileid.core.TSAUtils;
import vn.mobileid.pkix.ers.*;
import vn.mobileid.utils.Utils;

import java.io.*;
import java.util.List;

public class ERSTest {
    private static final String inputPdfPath = "src/test/java/files/input.pdf";
    private static final String outputPdfPath1 = "src/test/java/files/output_with_evidence_record-1.pdf";
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
        DSSDocument document = new FileDocument(inputXMLpath);
        XAdESService xadesService = new XAdESService(p12FilePath, p12Password, TSA_URL);
        DSSDocument xAdESDocument = xadesService.signXAdESDocument(document);
        xAdESDocument.save(outputXMLpath);

        PAdESService padesService = new PAdESService(p12FilePath, p12Password, TSA_URL);
    }



    public static void saveEvidenceRecordToFile(EvidenceRecord ev, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(ev.getEncoded());
        }
    }



    public static void validateASN1EvidenceRecord(DSSDocument document) throws IOException {
        ASN1EvidenceRecordAnalyzer analyzer = new ASN1EvidenceRecordAnalyzer(document);
        if (analyzer.isSupported(document)) {
            System.out.println("The Evidence Record is valid.");
        } else {
            System.out.println("The Evidence Record is invalid.");
        }
    }

    public static EvidenceRecord createEvidenceRecord(byte[] data1) throws Exception {
        ERSData ersData = new ERSByteData(data1);
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);
        ersGen.addData(ersData);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();
        tspReqGen.setCertReq(true);
        TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);

        TimeStampResponse tsResp = TSAUtils.getTimeStampResponse(tspReq.getEncoded());
        if (tsResp == null) {
            throw new IOException("Failed to retrieve timestamp response from TSA.");
        }
        Utils.saveTimeStampRequestToFile(tspReq, tspPath);
        Utils.saveTimeStampResponseToFile(tsResp, tsrPath);
        List<ERSArchiveTimeStamp> atss = ersGen.generateArchiveTimeStamps(tsResp);
        ERSEvidenceRecordGenerator evGen = new ERSEvidenceRecordGenerator(digestCalculatorProvider);
        List<ERSEvidenceRecord> evs = evGen.generate(atss);
        return evs.get(0).toASN1Structure();
    }








}