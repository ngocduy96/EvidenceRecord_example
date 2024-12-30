import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import vn.mobileid.core.EvidenceRecord;
import vn.mobileid.core.TSAUtils;
import vn.mobileid.pkix.ers.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;

public class EvidenceRecordSyntaxTest {
    public static void main(String[] args) {
        EvidenceRecordSyntaxTest test = new EvidenceRecordSyntaxTest();
        String inputPdfPath = "src/test/java/input.pdf";
        String outputErsPath = "src/test/java/output.ers";

        try {
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


    public EvidenceRecord createEvidenceRecord(byte[] data1) throws Exception {
        // 1. Tạo ERSData và DigestCalculator
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

        List<ERSArchiveTimeStamp> atss = ersGen.generateArchiveTimeStamps(tsResp);
        ERSEvidenceRecordGenerator evGen = new ERSEvidenceRecordGenerator(digestCalculatorProvider);
        List<ERSEvidenceRecord> evs = evGen.generate(atss);
        EvidenceRecord ev = evs.get(0).toASN1Structure();
        return ev;
    }

}
