import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.tsp.TimeStampResponse;
import vn.mobileid.core.MerkleTree;
import vn.mobileid.core.TSAUtils;
import vn.mobileid.pkix.xmlers.XMLEvidenceRecord;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class XMLERSTest {

    // Phương thức ký tài liệu XML
    public static DSSDocument signXmlDocument(String inputXmlPath, String p12FilePath, String p12Password) throws Exception {
        DSSDocument xmlDocument = new FileDocument(new File(inputXmlPath));

        // Tạo token chữ ký từ file P12
        Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken(p12FilePath, new KeyStore.PasswordProtection(p12Password.toCharArray()));
        DSSPrivateKeyEntry privateKeyEntry = signatureToken.getKeys().get(0);

        // Tạo tham số cho chữ ký
        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        parameters.setArchiveTimestampParameters(null);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());
        // Tạo dịch vụ XAdES và lấy dữ liệu để ký
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        XAdESService xadesService = new XAdESService(commonCertificateVerifier);
        ToBeSigned toBeSigned = xadesService.getDataToSign(xmlDocument, parameters);

        // Ký tài liệu
        SignatureValue signatureValue = signatureToken.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKeyEntry);
        return xadesService.signDocument(xmlDocument, parameters, signatureValue);
    }


    public static void main(String[] args) {
        try {
            List<String> inputFilePaths = List.of(
                    "src/test/java/files/Test.txt");

            // Bước 1: Băm từng file
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            ArrayList<String> hashList = new ArrayList<>();

            for (String inputFilePath : inputFilePaths) {
                File inputFile = new File(inputFilePath);
                try (FileInputStream fis = new FileInputStream(inputFile)) {
                    byte[] fileData = fis.readAllBytes(); // Đọc dữ liệu file
                    byte[] fileHash = digest.digest(fileData); // Băm dữ liệu
                    hashList.add(Base64.encodeBase64String(fileHash)); // Thêm hash vào danh sách
                }
            }
            //Bước 2: tạo cây băm
            MerkleTree merkleTree = new MerkleTree();
            String rootHash = merkleTree.createMerkleTree(hashList);
            XMLEvidenceRecord xmlEvidenceRecord = new XMLEvidenceRecord("1.0");

            // Bước 3: lấy roothash từ cây băm gửi lên TSA Lấy timestamp
            TimeStampResponse timeStampResponse = TSAUtils.getTimeStampResponse(rootHash.getBytes());
            byte[] timeStampToken = timeStampResponse.getTimeStampToken().getEncoded();
            String timeStampTokenBase64 = Base64.encodeBase64String(timeStampToken);
            System.out.println("Timestamp token: " + timeStampTokenBase64);

            List<String> timeStampData = List.of(timeStampTokenBase64);
            //Bước 4: Tạo ArchiveTimeStampSequence
            xmlEvidenceRecord.addArchiveTimeStampSequence(hashList, timeStampData);

            // Bước 5: Xuất ra file XMLERS chuẩn
            xmlEvidenceRecord.toXMLString();


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}