package vn.mobile.id.services.cades;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;

import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;

public class CAdES {

    private final String p12FilePath;
    private final String p12Password;
    private final String TSA_URL;

    public CAdES(String p12FilePath, String p12Password, String TSA_URL) {
        this.p12FilePath = p12FilePath;
        this.p12Password = p12Password;
        this.TSA_URL = TSA_URL;
    }

    public DSSDocument signCAdESDocument(DSSDocument document) throws Exception {
        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(p12FilePath, new KeyStore.PasswordProtection(p12Password.toCharArray()));
        DSSPrivateKeyEntry privateKeyEntry = signatureToken.getKeys().get(0);

        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());
        parameters.setCertificateChain(privateKeyEntry.getCertificateChain());

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setCheckRevocationForUntrustedChains(true);
        CAdESService cAdESService = new CAdESService(commonCertificateVerifier);
        ToBeSigned toBeSigned = cAdESService.getDataToSign(document, parameters);

        SignatureValue signatureValue = signatureToken.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKeyEntry);
        return cAdESService.signDocument(document, parameters, signatureValue);
    }

//    public static DSSDocument extendPAdESLTADocument(DSSDocument dssDocument) throws Exception {
//        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
//        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
//        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
//
//        CertificateVerifier cv = new CommonCertificateVerifier();
//        cv.setCrlSource(OnlineSources.onlineCRLSource());
//        cv.setOcspSource(OnlineSources.ocspSource());
//        cv.addTrustedCertSources(trustedCertSource);
//        cv.setCheckRevocationForUntrustedChains(true);
//
//        CAdESService padesService = new CAdESService(cv);
//        padesService.setTspSource(OnlineSources.onlineTSPSource());
//
//        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
//        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
//        return padesService.extendDocument(dssDocument, parameters);
//    }

//    public static void renewalTimestamp(DSSDocument document) throws Exception {
//        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
//        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
//        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
//
//        CertificateVerifier cv = new CommonCertificateVerifier();
//        cv.setCrlSource(OnlineSources.onlineCRLSource());
//        cv.setOcspSource(OnlineSources.ocspSource());
//        cv.addTrustedCertSources(trustedCertSource);
//        cv.setCheckRevocationForUntrustedChains(true);
//        cv.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());
//
//        CAdESService cadesService = new CAdESService(cv);
//        cadesService.setTspSource(OnlineSources.onlineTSPSource());
//
//        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
//        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
//    }

    public DSSDocument timestamping(DSSDocument documentToTimestamp) throws IOException {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File(p12FilePath), "PKCS12", p12Password.toCharArray());
        trustedCertificateSource.importAsTrusted(keystore);

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setTrustedCertSources(trustedCertificateSource);

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(TSA_URL);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());

        ASiCWithCAdESService service = new ASiCWithCAdESService(commonCertificateVerifier);
        service.setTspSource(onlineTSPSource);
        ASiCWithCAdESTimestampParameters timestampingParameters = new ASiCWithCAdESTimestampParameters();

// Specify the target container level
        timestampingParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        return service.timestamp(documentToTimestamp, timestampingParameters);
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
