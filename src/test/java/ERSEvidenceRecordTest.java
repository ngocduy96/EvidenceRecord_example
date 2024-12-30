import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;

import vn.mobileid.core.TSAUtils;
import vn.mobileid.pkix.ers.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import vn.mobileid.core.EvidenceRecord;

import java.util.List;

public class ERSEvidenceRecordTest {
    public static void main(String[] args) {

        String inputPdfPath = "src/test/java/input.pdf";
        String outputErsPath = "src/test/java/output.ers";

        try {

            byte[] pdf1Data = readFileToBytes(inputPdfPath);
            EvidenceRecord evidenceRecord = createEvidenceRecord(pdf1Data);
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

    public static EvidenceRecord createEvidenceRecord(byte[] data1) throws Exception {
        ERSData ersData = new ERSByteData(data1);
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);
        ersGen.addData(ersData);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();
        tspReqGen.setCertReq(true);
        TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);

        byte[] timeStampToken = null;
        try {
            // Call TSA to get the timestamp token
            timeStampToken = TSAUtils.getTimeStampToken(tspReq.getEncoded());
            if (timeStampToken == null) {
                throw new IOException("Failed to retrieve timestamp token from TSA.");
            }
        } catch (IOException e) {
            System.err.println("Error calling TSA: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }

        TimeStampResponse tsResp;
        try {
            tsResp = new TimeStampResponse(timeStampToken);
        } catch (TSPException e) {
            System.err.println("Error parsing timestamp response: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }

        List<ERSArchiveTimeStamp> atss = ersGen.generateArchiveTimeStamps(tsResp);
        ERSEvidenceRecordGenerator evGen = new ERSEvidenceRecordGenerator(digestCalculatorProvider);
        List<ERSEvidenceRecord> evs = evGen.generate(atss);
        EvidenceRecord ev = evs.get(0).toASN1Structure();
        return ev;
    }
}