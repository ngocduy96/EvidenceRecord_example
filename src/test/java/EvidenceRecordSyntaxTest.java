import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import vn.mobileid.core.EvidenceRecord;
import vn.mobileid.core.TSAUtils;
import vn.mobileid.pkix.ers.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.List;

public class EvidenceRecordSyntaxTest {
    private static final String inputPdfPath = "src/test/java/files/input.pdf";
    private static final String outputPdfPath = "src/test/java/files/output_with_evidence_record.pdf";
    private static final String outputERSPath = "src/test/java/files/evidence_record.ers";
    private static final String tsrPath = "src/test/java/files/input.tsr";
    private static final String tspPath = "src/test/java/files/input.tsp";
    private static final String p12FilePath = "src/test/java/files/keystore.p12";
    private static final String p12Password = "12345678";
    private static final String tspSource = "https://freetsa.org/tsr";

    public static void main(String[] args) {
        try {
            DSSDocument dssDocument = signDocument();
            dssDocument.save(outputPdfPath);

            byte[] data1 = Files.readAllBytes(Paths.get(outputPdfPath));
            EvidenceRecord ev = createEvidenceRecord(data1);
            saveEvidenceRecordToFile(ev.getEncoded(), outputERSPath);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static EvidenceRecord createEvidenceRecord(byte[] data1) throws Exception {

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
        saveTimeStampRequestToFile(tspReq, tspPath);
        saveTimeStampResponseToFile(tsResp, tsrPath);
        List<ERSArchiveTimeStamp> atss = ersGen.generateArchiveTimeStamps(tsResp);
        ERSEvidenceRecordGenerator evGen = new ERSEvidenceRecordGenerator(digestCalculatorProvider);
        List<ERSEvidenceRecord> evs = evGen.generate(atss);
        EvidenceRecord ev = evs.get(0).toASN1Structure();
        return ev;
    }

    public static void saveEvidenceRecordToFile(byte[] evidenceRecord, String outputFilePath) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(evidenceRecord);
            System.out.println("Evidence Record saved to: " + outputFilePath);
        }
    }

    public static DSSDocument signDocument() throws Exception {
        DSSDocument xmlDocument = new FileDocument(new File(inputPdfPath));

        // Tạo token chữ ký từ file P12
        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(p12FilePath, new KeyStore.PasswordProtection(p12Password.toCharArray()));
        DSSPrivateKeyEntry privateKeyEntry = signatureToken.getKeys().get(0);

        // Tạo tham số cho chữ ký
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        PAdESService padesService = new PAdESService(commonCertificateVerifier);
        ToBeSigned toBeSigned = padesService.getDataToSign(xmlDocument, parameters);

        // Ký tài liệu
        SignatureValue signatureValue = signatureToken.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKeyEntry);
        return padesService.signDocument(xmlDocument, parameters, signatureValue);
    }


    public static DSSDocument pdfTimestamping() throws IOException {
        DSSDocument documentToTimestamp = new FileDocument(inputPdfPath);
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File("src/test/java/keystore.p12"), "PKCS12", p12Password.toCharArray());
        trustedCertificateSource.importAsTrusted(keystore);

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setTrustedCertSources(trustedCertificateSource);
        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspSource);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        // Configure a PAdES service for PDF timestamping
        PAdESService service = new PAdESService(commonCertificateVerifier);
        service.setTspSource(onlineTSPSource);
        return service.timestamp(documentToTimestamp, new PAdESTimestampParameters());
    }

    public static DSSDocument signAndTimeStampDocument() throws Exception {
        DSSDocument document = new FileDocument(new File(inputPdfPath));
        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File("src/test/java/keystore.p12"), "PKCS12", p12Password.toCharArray());
        // Tạo token chữ ký từ file P12
        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(p12FilePath, new KeyStore.PasswordProtection(p12Password.toCharArray()));
        DSSPrivateKeyEntry privateKeyEntry = signatureToken.getKeys().get(0);

        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.importAsTrusted(keystore);
        // Tạo tham số cho chữ ký
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());
        parameters.setSignWithNotYetValidCertificate(true);
        parameters.setSignWithExpiredCertificate(true);

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspSource);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setTrustedCertSources(trustedCertificateSource);

        PAdESService padesService = new PAdESService(commonCertificateVerifier);
        padesService.setTspSource(onlineTSPSource);

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        padesService.timestamp(document, timestampParameters);

        ToBeSigned toBeSigned = padesService.getDataToSign(document, parameters);

        // Ký tài liệu
        SignatureValue signatureValue = signatureToken.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKeyEntry);
        return padesService.signDocument(document, parameters, signatureValue);
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
}
