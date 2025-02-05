package vn.mobile.id.services.pades;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
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
import vn.mobile.id.config.SignerConfig;
import vn.mobile.id.services.SignatureService;
import vn.mobile.id.sources.OnlineSources;
import eu.europa.esig.dss.pades.signature.PAdESService;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;

public class PAdES implements SignatureService {
    private final SignerConfig config;

    public PAdES(SignerConfig config) {
        this.config = config;
    }

    @Override
    public String extendLTA(String filePath) throws Exception {
        DSSDocument dssDocument = new FileDocument(filePath);
        Path path = Paths.get(filePath);
        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCrlSource(OnlineSources.onlineCRLSource());
        cv.setOcspSource(OnlineSources.ocspSource());
        cv.addTrustedCertSources(trustedCertSource);
        cv.setCheckRevocationForUntrustedChains(true);

        PAdESService padesService = new PAdESService(cv);
        padesService.setTspSource(OnlineSources.onlineTSPSource());

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        DSSDocument timestampedDocument = padesService.extendDocument(dssDocument, parameters);
        return saveSignedDocument(timestampedDocument, path);
    }

    @Override
    public DSSDocument renewalTimestamp(DSSDocument document) throws Exception {
        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCrlSource(OnlineSources.onlineCRLSource());
        cv.setOcspSource(OnlineSources.ocspSource());
        cv.addTrustedCertSources(trustedCertSource);
        cv.setCheckRevocationForUntrustedChains(true);
        cv.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());

        PAdESService padesService = new PAdESService(cv);
        padesService.setTspSource(OnlineSources.onlineTSPSource());

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return padesService.timestamp(document, timestampParameters);
    }


    @Override
    public String signDocument(String filePath) throws Exception {
        DSSDocument document = new FileDocument(filePath);
        Path path = Paths.get(filePath);
        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(config.getP12FilePath(), new KeyStore.PasswordProtection(config.getP12Password().toCharArray()));
        DSSPrivateKeyEntry privateKeyEntry = signatureToken.getKeys().get(0);

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());
        parameters.setCertificateChain(privateKeyEntry.getCertificateChain());

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setCheckRevocationForUntrustedChains(true);
        PAdESService padesService = new PAdESService(commonCertificateVerifier);
        ToBeSigned toBeSigned = padesService.getDataToSign(document, parameters);

        SignatureValue signatureValue = signatureToken.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKeyEntry);
        DSSDocument signedDocument = padesService.signDocument(document, parameters, signatureValue);
        return saveSignedDocument(signedDocument, path);

    }


    @Override
    public String timestampDocument(String filePath) throws Exception {
        DSSDocument document = new FileDocument(filePath);
        Path path = Paths.get(filePath);
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File(config.getP12FilePath()), "PKCS12", config.getP12Password().toCharArray());
        trustedCertificateSource.importAsTrusted(keystore);

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setTrustedCertSources(trustedCertificateSource);

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(config.getTSA_URL());
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        PAdESService service = new PAdESService(commonCertificateVerifier);
        service.setTspSource(onlineTSPSource);
        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        DSSDocument signedDocument = service.timestamp(document, timestampParameters);
        return saveSignedDocument(signedDocument, path);
    }

    @Override
    public Reports validateDocument(DSSDocument document) throws Exception {
        PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
        return pdfDocumentValidator.validateDocument();
    }
}
