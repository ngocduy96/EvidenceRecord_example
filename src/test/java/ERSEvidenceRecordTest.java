import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;

import org.bouncycastle.util.Store;
import vn.mobileid.pkix.ers.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import vn.mobileid.core.EvidenceRecord;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

public class ERSEvidenceRecordTest {
    public static void main(String[] args) throws IOException {
        ERSEvidenceRecordTest test = new ERSEvidenceRecordTest();
        String inputPdfPath = "src/test/java/input.pdf";
        String outputErsPath = "src/test/java/output.ers";

        try {
            test.setUp();
            byte[] pdf1Data = readFileToBytes(inputPdfPath);
            EvidenceRecord evidenceRecord = test.createEvidenceRecord(pdf1Data);
            saveEvidenceRecordToFile(evidenceRecord, outputErsPath);
            System.out.println("Evidence Record đã được tạo và lưu thành công!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] readFileToBytes(String filePath) throws IOException {
        File file = new File(filePath);
        return Files.readAllBytes(file.toPath());
    }

    public static void saveEvidenceRecordToFile(EvidenceRecord evidenceRecord, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(evidenceRecord.getEncoded());
        }
    }

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public EvidenceRecord createEvidenceRecord(byte[] data1) throws Exception {
//        ERSDataGroup ersData = new ERSDataGroup(
//                new ERSByteData(data1),
//                new ERSByteData(data2));
        ERSData ersData = new ERSByteData(data1);
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        ersGen.addData(ersData);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();

        tspReqGen.setCertReq(true);
        TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);
        String p12FilePath = "src/test/java/keystore.p12";
        String p12Password = "12345678";
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (FileInputStream fis = new FileInputStream(p12FilePath)) {
            keyStore.load(fis, p12Password.toCharArray());
        }
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, p12Password.toCharArray());
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        List certList = new ArrayList();
        certList.add(cert);
        Store certs = new JcaCertStore(certList);

        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
                infoGeneratorBuilder
                        .build(new JcaContentSignerBuilder("SHA256withRSA")
                                .setProvider(BC)
                                .build(privateKey), cert),
                new SHA1DigestCalculator(),
                new ASN1ObjectIdentifier("1.2.3"));

        tsTokenGen.addCertificates(certs);
        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);
        TimeStampResponse tsResp;

        try {
            tsResp = tsRespGen.generateGrantedResponse(tspReq, new BigInteger("23"), new Date());
        } catch (TSPException e) {
            tsResp = tsRespGen.generateRejectedResponse(e);
        }
        List<ERSArchiveTimeStamp> atss = ersGen.generateArchiveTimeStamps(tsResp);
        ERSEvidenceRecordGenerator evGen = new ERSEvidenceRecordGenerator(digestCalculatorProvider);
        List<ERSEvidenceRecord> evs = evGen.generate(atss);
        EvidenceRecord ev = evs.get(0).toASN1Structure();
        return ev;
    }
}
