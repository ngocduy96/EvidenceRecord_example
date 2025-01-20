package vn.mobileid.services.pades;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import vn.mobileid.sources.OnlineSources;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;

public class PAdESService {

    private final String p12FilePath;
    private final String p12Password;
    private final String TSA_URL;

    public PAdESService(String p12FilePath, String p12Password, String TSA_URL) {
        this.p12FilePath = p12FilePath;
        this.p12Password = p12Password;
        this.TSA_URL = TSA_URL;
    }

    public DSSDocument signPAdESDocument(DSSDocument xmlDocument) throws Exception {
        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(p12FilePath, new KeyStore.PasswordProtection(p12Password.toCharArray()));
        DSSPrivateKeyEntry privateKeyEntry = signatureToken.getKeys().get(0);

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());
        parameters.setCertificateChain(privateKeyEntry.getCertificateChain());

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setCheckRevocationForUntrustedChains(true);
        eu.europa.esig.dss.pades.signature.PAdESService padesService = new eu.europa.esig.dss.pades.signature.PAdESService(commonCertificateVerifier);
        ToBeSigned toBeSigned = padesService.getDataToSign(xmlDocument, parameters);

        SignatureValue signatureValue = signatureToken.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKeyEntry);
        return padesService.signDocument(xmlDocument, parameters, signatureValue);
    }
    public static DSSDocument extendPAdESLTADocument(DSSDocument dssDocument) throws Exception {
        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCrlSource(OnlineSources.onlineCRLSource());
        cv.setOcspSource(OnlineSources.ocspSource());
        cv.addTrustedCertSources(trustedCertSource);
        cv.setCheckRevocationForUntrustedChains(true);

        eu.europa.esig.dss.pades.signature.PAdESService padesService = new eu.europa.esig.dss.pades.signature.PAdESService(cv);
        padesService.setTspSource(OnlineSources.onlineTSPSource());

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return padesService.extendDocument(dssDocument, parameters);
    }
    public static void renewalTimestamp(DSSDocument document) throws Exception {
        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCrlSource(OnlineSources.onlineCRLSource());
        cv.setOcspSource(OnlineSources.ocspSource());
        cv.addTrustedCertSources(trustedCertSource);
        cv.setCheckRevocationForUntrustedChains(true);
        cv.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());

        eu.europa.esig.dss.pades.signature.PAdESService padesService = new eu.europa.esig.dss.pades.signature.PAdESService(cv);
        padesService.setTspSource(OnlineSources.onlineTSPSource());

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    }

    public DSSDocument pdfTimestamping(DSSDocument documentToTimestamp) throws IOException {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File(p12FilePath), "PKCS12", p12Password.toCharArray());
        trustedCertificateSource.importAsTrusted(keystore);

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setTrustedCertSources(trustedCertificateSource);

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(TSA_URL);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        eu.europa.esig.dss.pades.signature.PAdESService service = new eu.europa.esig.dss.pades.signature.PAdESService(commonCertificateVerifier);
        service.setTspSource(onlineTSPSource);
        return service.timestamp(documentToTimestamp, new PAdESTimestampParameters());
    }
    public static String validateTimestampedDocument(DSSDocument document) {
        PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
        Reports reports = pdfDocumentValidator.validateDocument();
        System.out.println(reports.getXmlSimpleReport());
        return reports.getXmlSimpleReport();
    }


}
