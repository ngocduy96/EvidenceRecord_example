package vn.mobileid.services.xades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import vn.mobileid.sources.OnlineSources;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;

public class XAdES {
    private final String p12FilePath;
    private final String p12Password;
    private final String TSA_URL;

    public XAdES(String p12FilePath, String p12Password, String TSA_URL) {
        this.p12FilePath = p12FilePath;
        this.p12Password = p12Password;
        this.TSA_URL = TSA_URL;
    }
    public  DSSDocument signXAdESDocument(DSSDocument xmlDocument) throws Exception {
        DigestDocument digestDocument = new DigestDocument();
        digestDocument.addDigest(DigestAlgorithm.SHA256, xmlDocument.getDigestValue(DigestAlgorithm.SHA256));

        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(p12FilePath, new KeyStore.PasswordProtection(p12Password.toCharArray()));
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
        eu.europa.esig.dss.xades.signature.XAdESService xAdESService = new eu.europa.esig.dss.xades.signature.XAdESService(cv);

        // Get the SignedInfo segment that need to be signed.
        ToBeSigned toBeSigned = xAdESService.getDataToSign(xmlDocument, parameters);

        DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
        SignatureValue signatureValue = signatureToken.sign(toBeSigned, digestAlgorithm, privateKeyEntry);
        //provide 1st parameter as digestDocument to keep the original document private
        //provide 2nd parameter as original document to keep the original document public
        return xAdESService.signDocument(digestDocument, parameters, signatureValue);
    }
    public DSSDocument xmlTimestamping(DSSDocument documentToTimestamp) throws IOException {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File(p12FilePath), "PKCS12", p12Password.toCharArray());
        trustedCertificateSource.importAsTrusted(keystore);

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        commonCertificateVerifier.setTrustedCertSources(trustedCertificateSource);

        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(TSA_URL);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        eu.europa.esig.dss.xades.signature.XAdESService service = new eu.europa.esig.dss.xades.signature.XAdESService(commonCertificateVerifier);
        service.setTspSource(onlineTSPSource);
        return service.timestamp(documentToTimestamp, new XAdESTimestampParameters());
    }



    public static DSSDocument extendXAdESLTADocument(DSSDocument dssDocument) throws Exception {
        TrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setCrlSource(OnlineSources.onlineCRLSource());
        cv.setOcspSource(OnlineSources.ocspSource());
        cv.addTrustedCertSources(trustedCertSource);
        cv.setCheckRevocationForUntrustedChains(true);

        eu.europa.esig.dss.xades.signature.XAdESService xAdESService = new eu.europa.esig.dss.xades.signature.XAdESService(cv);
        xAdESService.setTspSource(OnlineSources.onlineTSPSource());

        XAdESTimestampParameters timestampParameters = new XAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return xAdESService.extendDocument(dssDocument, parameters);
    }
}
