import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecord;
import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecordAnalyzer;
import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecordValidator;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordValidator;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidatorFactory;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.*;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
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

import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class EvidenceRecordSyntaxTest {
    private static final String inputPdfPath = "src/test/java/files/input.pdf";
    private static final String outputPdfPath1 = "src/test/java/files/output_with_evidence_record-1.pdf";
    //    private static final String outputPdfPath2 = "src/test/java/files/output_with_evidence_record-2.pdf";
//    private static final String outputPdfPath3 = "src/test/java/files/output_with_evidence_record-3.pdf";
    private static final String outputReportPath = "src/test/java/files/report.xml";
    private static final String inputXMLpath = "src/test/java/files/input.xml";
    private static final String outputXMLpath = "src/test/java/files/output.xml";

    private static final String outputERSPath = "src/test/java/files/evidence_record.ers";
    private static final String tsrPath = "src/test/java/files/input.tsr";
    private static final String tspPath = "src/test/java/files/input.tsp";
    private static final String p12FilePath = "src/test/java/files/duynguyen.p12";
    private static final String p12Password = "12345678";
    //    private static final String TSA_URL = "https://freetsa.org/tsr";
//    private static final String TSA_URL = "http://timestamp.digicert.com";
    private static final String TSA_URL = "http://ca.gov.vn/tsa";

    public static void main(String[] args) throws Exception {


        DSSDocument document = new FileDocument(inputXMLpath);
//        byte[] data = document.getDigestValue(DigestAlgorithm.SHA256);
//        EvidenceRecord ev = createEvidenceRecord(data);
//        saveEvidenceRecordToFile(ev, outputERSPath);
//        DSSDocument document2 = new FileDocument(outputERSPath);
//        validateASN1EvidenceRecord(document);
        //        DSSDocument dssDocument = signDocument(document);
        DSSDocument xAdESDocument = signXAdESDocument(document);
        xAdESDocument.save(outputXMLpath);
//        DSSDocument input = extendLTADocument(dssDocument);
//        input.save(outputPdfPath1);

//        DSSDocument document = new FileDocument(outputPdfPath2);
//        String report = validateTimestampedDocument(document);

    }

    public static DSSDocument signPAdESDocument(DSSDocument xmlDocument) throws Exception {

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
        commonCertificateVerifier.setCheckRevocationForUntrustedChains(true);
        PAdESService padesService = new PAdESService(commonCertificateVerifier);
        ToBeSigned toBeSigned = padesService.getDataToSign(xmlDocument, parameters);

        // Ký tài liệu
        SignatureValue signatureValue = signatureToken.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKeyEntry);
        return padesService.signDocument(xmlDocument, parameters, signatureValue);
    }

    public static DSSDocument signXAdESDocument(DSSDocument xmlDocument) throws Exception {

        // Tạo token chữ ký từ file P12
        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(p12FilePath, new KeyStore.PasswordProtection(p12Password.toCharArray()));
        DSSPrivateKeyEntry privateKeyEntry = signatureToken.getKeys().get(0);

        // Tạo tham số cho chữ ký
        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCheckRevocationForUntrustedChains(true);
        XAdESService xAdESService = new XAdESService(cv);
        ToBeSigned toBeSigned = xAdESService.getDataToSign(xmlDocument, parameters);

        // Ký tài liệu
        SignatureValue signatureValue = signatureToken.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKeyEntry);
        return xAdESService.signDocument(xmlDocument, parameters, signatureValue);
    }

    public static void saveEvidenceRecordToFile(EvidenceRecord ev, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(ev.getEncoded());
        }
    }

    public static String validateTimestampedDocument(DSSDocument document) {
        PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
        Reports reports = pdfDocumentValidator.validateDocument();
        System.out.println(reports.getXmlSimpleReport());
        return reports.getXmlSimpleReport();
    }

    public static void validateASN1EvidenceRecord(DSSDocument document) throws IOException {
        ASN1EvidenceRecordAnalyzer analyzer = new ASN1EvidenceRecordAnalyzer(document);
        // Kiểm tra tính hợp lệ của Evidence Record
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


    public DSSDocument pdfTimestamping(DSSDocument documentToTimestamp) throws IOException {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File(p12FilePath), "PKCS12", p12Password.toCharArray());
        trustedCertificateSource.importAsTrusted(keystore);

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setTrustedCertSources(trustedCertificateSource);

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(TSA_URL);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        // Configure a PAdES service for PDF timestamping
        PAdESService service = new PAdESService(commonCertificateVerifier);
        service.setTspSource(onlineTSPSource);
        return service.timestamp(documentToTimestamp, new PAdESTimestampParameters());
    }

    public static DSSDocument extendLTADocument(DSSDocument dssDocument) throws Exception {
        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.getCertificateSourceType();
        // Tạo tham số cho chữ ký
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCrlSource(onlineCRLSource());
        cv.setOcspSource(ocspSource());
        cv.addTrustedCertSources(trustedCertSource);
        cv.setCheckRevocationForUntrustedChains(true);
//        cv.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
        PAdESService padesService = new PAdESService(cv);
        padesService.setTspSource(onlineTSPSource());

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return padesService.extendDocument(dssDocument, parameters);
    }

    public static void renewalTimestamp(DSSDocument document) throws Exception {
        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.getCertificateSourceType();
        // Tạo tham số cho chữ ký
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCrlSource(onlineCRLSource());
        cv.setOcspSource(ocspSource());
        cv.addTrustedCertSources(trustedCertSource);
        cv.setCheckRevocationForUntrustedChains(true);
        cv.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());
        PAdESService padesService = new PAdESService(cv);
        padesService.setTspSource(onlineTSPSource());

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

    }

    public static void saveTimeStampRequestToFile(TimeStampRequest tspReq, String outputFilePath) throws
            IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(tspReq.getEncoded());
        }
    }

    public static void saveTimeStampResponseToFile(TimeStampResponse tsResp, String outputFilePath) throws
            IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(tsResp.getEncoded());
        }
    }

    private static OnlineTSPSource onlineTSPSource() {
        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(TSA_URL);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        return onlineTSPSource;
    }

    private static OnlineCRLSource onlineCRLSource() {
        OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
        onlineCRLSource.setDataLoader(dataLoader());
        return onlineCRLSource;
    }

    private static OnlineOCSPSource ocspSource() {
        return new OnlineOCSPSource();
    }

    private static CommonsDataLoader dataLoader() {
        CommonsDataLoader dataLoader = new CommonsDataLoader();
        dataLoader.setProxyConfig(null);
        return dataLoader;
    }
}
