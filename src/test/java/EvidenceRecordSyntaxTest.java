import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import vn.mobileid.core.EvidenceRecord;
import vn.mobileid.core.TSAUtils;
import vn.mobileid.pkix.ers.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Base64;
import java.util.List;

import com.itextpdf.kernel.pdf.*;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;

public class EvidenceRecordSyntaxTest {
    private static final String inputPdfPath = "src/test/java/input.pdf";
    private static final String outputPdfPath = "src/test/java/output_with_evidence_record.pdf";
    private static final String p12FilePath = "src/test/java/keystore.p12";
    private static final String inputXmlPath = "src/test/java/input.xml";
    private static final String p12Password = "12345678";

    public static void main(String[] args) {
        EvidenceRecordSyntaxTest test = new EvidenceRecordSyntaxTest();

        try {
            byte[] pdf1Data = readFileToBytes(inputPdfPath);
            EvidenceRecord evidenceRecord = test.createEvidenceRecord(pdf1Data);
            signDocument(new XAdESTimestampParameters(), listTimestampToken);

            System.out.println("Evidence Record đã được tạo và lưu thành công!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] readFileToBytes(String filePath) throws IOException {
        File file = new File(filePath);
        return Files.readAllBytes(file.toPath());
    }


    public EvidenceRecord createEvidenceRecord(byte[] data1) throws Exception {
        // 1. Tạo ERSData và DigestCalculator
        ERSData ersData = new ERSByteData(data1);
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        // 2. Tạo ERSArchiveTimeStampGenerator
        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);
        ersGen.addData(ersData);

        // 3. Tạo TimeStampRequest
        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();
        tspReqGen.setCertReq(true);
        TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);

        TimeStampResponse tsResp = TSAUtils.getTimeStampResponse(tspReq.getEncoded());
        if (tsResp == null) {
            throw new IOException("Failed to retrieve timestamp response from TSA.");
        }
        saveTimeStampRequestToFile(tspReq, "src/test/java/input.tsq");
        saveTimeStampResponseToFile(tsResp, "src/test/java/input.tsr");
        List<ERSArchiveTimeStamp> atss = ersGen.generateArchiveTimeStamps(tsResp);
        ERSEvidenceRecordGenerator evGen = new ERSEvidenceRecordGenerator(digestCalculatorProvider);
        List<ERSEvidenceRecord> evs = evGen.generate(atss);
        EvidenceRecord ev = evs.get(0).toASN1Structure();
        return ev;
    }

    public static void saveTimeStampRequestToFile(TimeStampRequest tspReq, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(tspReq.getEncoded());
        }
    }

    public static void saveTimeStampResponseToFile(TimeStampResponse tsResp, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(tsResp.getEncoded());
        }
    }

    public static DSSDocument signDocument(XAdESTimestampParameters xAdESTimestampParameters, List<TimestampToken> listTimestampToken) throws Exception {
        DSSDocument xmlDocument = new FileDocument(new File(inputXmlPath));

        // Tạo token chữ ký từ file P12
        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(p12FilePath, new KeyStore.PasswordProtection(p12Password.toCharArray()));
        DSSPrivateKeyEntry privateKeyEntry = signatureToken.getKeys().get(0);

        // Tạo tham số cho chữ ký
        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        parameters.setArchiveTimestampParameters(xAdESTimestampParameters);
        parameters.setContentTimestamps(timestampToken);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());
        // Tạo dịch vụ XAdES và lấy dữ liệu để ký
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        XAdESService xadesService = new XAdESService(commonCertificateVerifier);
        ToBeSigned toBeSigned = xadesService.getDataToSign(xmlDocument, parameters);

        // Ký tài liệu
        SignatureValue signatureValue = signatureToken.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKeyEntry);
        return xadesService.signDocument(xmlDocument, parameters, signatureValue);
    }

}
