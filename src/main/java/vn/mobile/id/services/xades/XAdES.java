package vn.mobile.id.services.xades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.*;
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
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import vn.mobile.id.config.SignerConfig;
import vn.mobile.id.services.SignatureService;
import vn.mobile.id.sources.OnlineSources;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;

public class XAdES implements SignatureService {
    private final SignerConfig config;

    public XAdES(SignerConfig config) {
        this.config = config;
    }

    @Override
    public String signDocument(String filePath) throws Exception {
        DSSDocument document = new FileDocument(filePath);
        Path path = Paths.get(filePath);
        DigestDocument digestDocument = new DigestDocument();
        digestDocument.addDigest(DigestAlgorithm.SHA256, document.getDigestValue(DigestAlgorithm.SHA256));

        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(config.getP12FilePath(), new KeyStore.PasswordProtection(config.getP12Password().toCharArray()));
        DSSPrivateKeyEntry privateKeyEntry = signatureToken.getKeys().get(0);

        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        // Set the detached packaging, as a digest only will be included into the signature, and the original content
        parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());
        parameters.setCertificateChain(privateKeyEntry.getCertificateChain());

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCheckRevocationForUntrustedChains(true);
        XAdESService xAdESService = new XAdESService(cv);

        // Get the SignedInfo segment that need to be signed.
        ToBeSigned toBeSigned = xAdESService.getDataToSign(document, parameters);

        DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
        SignatureValue signatureValue = signatureToken.sign(toBeSigned, digestAlgorithm, privateKeyEntry);
        //provide 1st parameter as digestDocument to keep the original document private
        //provide 2nd parameter as original document to keep the original document public
        DSSDocument signedDocument = xAdESService.signDocument(digestDocument, parameters, signatureValue);
        return saveSignedDocument(signedDocument, path);

    }

    @Override
    public String timestampDocument(String filePath) throws Exception {
        DSSDocument documentToTimestamp = new FileDocument(filePath);
        Path path = Paths.get(filePath);
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File(config.getP12FilePath()), "PKCS12", config.getP12Password().toCharArray());
        trustedCertificateSource.importAsTrusted(keystore);

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setTrustedCertSources(trustedCertificateSource);

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(config.getTSA_URL());
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        XAdESService service = new XAdESService(commonCertificateVerifier);
        service.setTspSource(onlineTSPSource);
        DSSDocument timestampedDocument = service.timestamp(documentToTimestamp, new XAdESTimestampParameters());
        return saveSignedDocument(timestampedDocument, path);
    }


    @Override
    public String extendLTA(String filePath) throws Exception {
        DSSDocument dssDocument = new FileDocument(filePath);
        Path path = Paths.get(filePath);
        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCrlSource(OnlineSources.onlineCRLSource());
        cv.setOcspSource(OnlineSources.ocspSource());
        cv.addTrustedCertSources(trustedCertSource);
        cv.setCheckRevocationForUntrustedChains(true);

        XAdESService xAdESService = new XAdESService(cv);
        xAdESService.setTspSource(OnlineSources.onlineTSPSource());

        XAdESTimestampParameters timestampParameters = new XAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        DSSDocument timestampedDocument = xAdESService.extendDocument(dssDocument, parameters);
        return saveSignedDocument(timestampedDocument, path);
    }

    @Override
    public DSSDocument renewalTimestamp(DSSDocument document) throws Exception {
        return null;
    }

    @Override
    public Reports validateDocument(DSSDocument document) throws Exception {
        return null;
    }
}
