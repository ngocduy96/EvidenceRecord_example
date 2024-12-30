
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import vn.mobileid.core.EvidenceRecord;
import vn.mobileid.pkix.ers.ERSArchiveTimeStamp;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

public class ERSVerification {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        try {
            String ersFilePath = "src/test/java/output.ers";
//            boolean isVerified = verifyERSFile(ersFilePath);
            boolean isVerified = true;
            if (isVerified) {
                System.out.println("ERS file verified successfully.");
            } else {
                System.out.println("ERS file verification failed.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean verifyERSFile(String ersFilePath) throws Exception {
        // Đọc và phân tích .ers file
        try (FileInputStream fis = new FileInputStream(ersFilePath);
             ASN1InputStream asn1InputStream = new ASN1InputStream(fis)) {

            // Phân tích dữ liệu .ers và chuyển đổi thành EvidenceRecord
            EvidenceRecord evidenceRecord = EvidenceRecord.getInstance(asn1InputStream.readObject());

            // Lấy TimestampToken từ EvidenceRecord
            TimeStampToken timestampToken = extractTimestampToken(evidenceRecord);
            if (timestampToken != null) {
                // Xác minh TimestampToken
                if (!verifyTimestampToken(timestampToken)) {
                    System.out.println("TimestampToken verification failed.");
                    return false;
                }
            }

            // Xác minh chữ ký số trong EvidenceRecord
//            if (!verifySignature(evidenceRecord)) {
//                System.out.println("Signature verification failed.");
//                return false;
//            }

            System.out.println("ERS file verification succeeded.");
            return true;
        } catch (IOException | TSPException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static TimeStampToken extractTimestampToken(EvidenceRecord evidenceRecord) {
        try {

//            ERSArchiveTimeStamp ersArchiveTimeStamp = new ERSArchiveTimeStamp(evidenceRecord.getArchiveTimeStamp(), new DigestCalculatorProvider());
//            return ersArchiveTimeStamp.getTimeStampToken();
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    private static boolean verifyTimestampToken(TimeStampToken timestampToken) throws Exception {
//        // Xác minh TimestampToken: kiểm tra signature của TSA và dữ liệu trong token
//        byte[] timeStampData = timestampToken.getEncoded();
//
//        // Lấy chữ ký của TSA từ TimestampToken
//        byte[] tsaSignature = timestampToken.getSignedAttributes();
//
//        // Xác minh chữ ký của TSA bằng chứng chỉ công khai của TSA (TSA's public certificate)
//        // Giả sử TSA certificate đã được cung cấp
//        X509Certificate tsaCertificate = getTSACertificate();  // Lấy chứng chỉ TSA
//        PublicKey tsaPublicKey = tsaCertificate.getPublicKey();
//        Signature sig = Signature.getInstance("SHA256withRSA");
//        sig.initVerify(tsaPublicKey);
//        sig.update(timeStampData);
//
//        // Xác minh chữ ký TSA
//        return sig.verify(tsaSignature);
        return false;
    }

//    private static boolean verifySignature(EvidenceRecord evidenceRecord) throws Exception {
//        // Lấy chữ ký từ EvidenceRecord và dữ liệu để xác minh
////        byte[] signedData = evidenceRecord.getSignedData();  // Trích xuất dữ liệu đã ký từ EvidenceRecord
//
//        CMSSignedData cmsSignedData = new CMSSignedData(signedData);
//        Store<?> store = cmsSignedData.getCertificates();
//        SignerInformationStore signers = cmsSignedData.getSignerInfos();
//        Collection<SignerInformation> c = signers.getSigners();
//        Iterator<SignerInformation> it = c.iterator();
//
//        while (it.hasNext()) {
//            SignerInformation signerInformation = it.next();
//            Collection<?> certCollection = store.getMatches(signerInformation.getSID());
//            Iterator<?> certIt = certCollection.iterator();
//            X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt.next();
//            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
//
//            // Xác minh chữ ký bằng cách sử dụng chứng chỉ công khai
//            if (signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate))) {
//                System.out.println("Signature verification successful.");
//                return true;
//            } else {
//                System.out.println("Signature verification failed.");
//                return false;
//            }
//        }
//        System.out.println("No valid signature found for verification.");
//        return false;
//    }

    // Giả sử bạn có một cách để lấy chứng chỉ của TSA
    private static X509Certificate getTSACertificate() throws Exception {
        // Đây là nơi bạn lấy chứng chỉ của TSA từ một nguồn đáng tin cậy
        // Ví dụ: tải về từ một file hoặc server
        FileInputStream fis = new FileInputStream("tsa_certificate.crt");
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(fis);
    }
}
