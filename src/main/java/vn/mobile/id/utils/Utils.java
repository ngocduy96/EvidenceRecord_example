package vn.mobile.id.utils;

import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecordAnalyzer;
import eu.europa.esig.dss.model.DSSDocument;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import vn.mobile.id.core.EvidenceRecord;
import vn.mobile.id.core.TSAUtils;
import vn.mobile.id.ers.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;

public class Utils {
    private final String tspPath;
    private final String tsrPath;

    public Utils(String p12FilePath, String p12Password) {
        this.tspPath = "src/test/java/files/input.tsp";
        this.tsrPath = "src/test/java/files/input.tsr";
    }

    public static void saveTimeStampRequestToFile(TimeStampRequest tspReq, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(tspReq.getEncoded());
        }
    }

    public static void saveTimeStampResponseToFile(TimeStampResponse tsResp, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(tsResp.getEncoded());
        }
    }

    public static void saveEvidenceRecordToFile(EvidenceRecord ev, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
            fos.write(ev.getEncoded());
        }
    }

    public static void validateASN1EvidenceRecord(DSSDocument document) throws IOException {
        ASN1EvidenceRecordAnalyzer analyzer = new ASN1EvidenceRecordAnalyzer(document);
        if (analyzer.isSupported(document)) {
            System.out.println("The Evidence Record is valid.");
        } else {
            System.out.println("The Evidence Record is invalid.");
        }
    }

    public EvidenceRecord createEvidenceRecord(byte[] data1) throws Exception {
        ERSData ersData = new ERSByteData(data1);
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);
        ersGen.addData(ersData);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();
        tspReqGen.setCertReq(true);
        TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);

        TimeStampResponse tsResp = TSAUtils.getTimeStampResponse(tspReq.getEncoded());
        if (tsResp == null) {
            throw new IOException("Failed to retrieve timestamp response from TSA.");
        }
        Utils.saveTimeStampRequestToFile(tspReq, tspPath);
        Utils.saveTimeStampResponseToFile(tsResp, tsrPath);
        List<ERSArchiveTimeStamp> atss = ersGen.generateArchiveTimeStamps(tsResp);
        ERSEvidenceRecordGenerator evGen = new ERSEvidenceRecordGenerator(digestCalculatorProvider);
        List<ERSEvidenceRecord> evs = evGen.generate(atss);
        return evs.get(0).toASN1Structure();
    }
}
