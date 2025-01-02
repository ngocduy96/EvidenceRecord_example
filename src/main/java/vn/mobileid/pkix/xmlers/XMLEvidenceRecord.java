package vn.mobileid.pkix.xmlers;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.*;
import vn.mobileid.core.MerkleTree;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class XMLEvidenceRecord {

    private final Document document;
    private final Element evidenceRecord;

    public XMLEvidenceRecord(String version) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        this.document = builder.newDocument();

        // Tạo node gốc EvidenceRecord
        this.evidenceRecord = document.createElement("EvidenceRecord");
        this.evidenceRecord.setAttribute("Version", version);
        this.evidenceRecord.setAttribute("xmlns", "urn:ietf:params:xml:ns:ers");
        this.document.appendChild(this.evidenceRecord);
    }


    // Thêm EncryptionInformation
    public void addEncryptionInformation(String encryptionType, String encryptionValue) {
        if (encryptionType == null || encryptionValue == null) {
            throw new IllegalArgumentException("Encryption type and value must not be null.");
        }

        Element encryptionInformation = document.createElement("EncryptionInformation");

        Element encryptionTypeElem = document.createElement("EncryptionInformationType");
        encryptionTypeElem.setTextContent(encryptionType);
        encryptionInformation.appendChild(encryptionTypeElem);

        Element encryptionValueElem = document.createElement("EncryptionInformationValue");
        encryptionValueElem.setTextContent(encryptionValue);
        encryptionInformation.appendChild(encryptionValueElem);

        this.evidenceRecord.appendChild(encryptionInformation);
    }

    // Thêm SupportingInformationList
    public void addSupportingInformationList(List<String> types, List<String> data) {
        if (types == null || data == null || types.size() != data.size()) {
            throw new IllegalArgumentException("Types and data must not be null and must have the same size.");
        }

        Element supportingInfoList = document.createElement("SupportingInformationList");

        for (int i = 0; i < types.size(); i++) {
            Element supportingInfo = document.createElement("SupportingInformation");
            supportingInfo.setAttribute("Type", types.get(i));
            supportingInfo.setTextContent(data.get(i));
            supportingInfoList.appendChild(supportingInfo);
        }

        this.evidenceRecord.appendChild(supportingInfoList);
    }

    // Thêm ArchiveTimeStampSequence
    public void addArchiveTimeStampSequence(ArrayList<String> hashList, List<String> timeStampData) throws NoSuchAlgorithmException {
        if (timeStampData == null || timeStampData.isEmpty()) {
            throw new IllegalArgumentException("TimeStamp data must not be null or empty.");
        }

        Element archiveTimeStampSequence = document.createElement("ArchiveTimeStampSequence");

        int order = 1;
        for (String data : timeStampData) {

            Element archiveTimeStampChain = createArchiveTimeStampChain(hashList, data, order);
            archiveTimeStampSequence.appendChild(archiveTimeStampChain);
            order++;
        }

        this.evidenceRecord.appendChild(archiveTimeStampSequence);
    }

    // Tạo ArchiveTimeStampChain
    private Element createArchiveTimeStampChain(ArrayList<String> hashList, String data, int order) throws NoSuchAlgorithmException {
        Element archiveTimeStampChain = document.createElement("ArchiveTimeStampChain");
        archiveTimeStampChain.setAttribute("Order", String.valueOf(order));

        Element digestMethod = document.createElement("DigestMethod");
        digestMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
        archiveTimeStampChain.appendChild(digestMethod);

        Element canonicalizationMethod = document.createElement("CanonicalizationMethod");
        canonicalizationMethod.setAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        archiveTimeStampChain.appendChild(canonicalizationMethod);

        Element archiveTimeStamp = createArchiveTimeStamp(hashList, data, order);
        archiveTimeStampChain.appendChild(archiveTimeStamp);

        return archiveTimeStampChain;
    }

    private Element createArchiveTimeStamp(ArrayList<String> hashList, String data, int order) throws NoSuchAlgorithmException {
        Element archiveTimeStamp = document.createElement("ArchiveTimeStamp");
        archiveTimeStamp.setAttribute("Order", String.valueOf(order));

        // Xây dựng HashTree
        Element hashTree = setHashTree(hashList);
        archiveTimeStamp.appendChild(hashTree);

        // Tạo TimeStamp
        Element timeStamp = setTimeStamp(data);
        archiveTimeStamp.appendChild(timeStamp);

        return archiveTimeStamp;
    }

    private Element setHashTree(ArrayList<String> hashList) throws NoSuchAlgorithmException {
        if (hashList == null || hashList.isEmpty()) {
            throw new IllegalArgumentException("Hash list must not be null or empty.");
        }

        // Tạo phần tử gốc HashTree
        Element hashTree = document.createElement("HashTree");

        // Duyệt qua danh sách hashList
        for (int i = 0; i < hashList.size(); i++) {
            String hashValue = hashList.get(i);

            // Tạo phần tử Sequence
            Element sequence = document.createElement("Sequence");
            sequence.setAttribute("Order", String.valueOf(i + 1));

            // Gắn DigestValue vào Sequence
            Element digestValueElement = document.createElement("DigestValue");
            digestValueElement.setTextContent(hashValue); // Hash đã được encode sẵn dưới dạng Base64
            sequence.appendChild(digestValueElement);

            // Gắn Sequence vào HashTree
            hashTree.appendChild(sequence);
        }

        return hashTree;
    }

    // Tạo TimeStamp
    private Element setTimeStamp(String data) {
        Element timeStamp = document.createElement("TimeStamp");

        Element timeStampToken = document.createElement("TimeStampToken");
        timeStampToken.setAttribute("Type", "RFC3161");
        timeStampToken.setTextContent(data);
        timeStamp.appendChild(timeStampToken);

        return timeStamp;
    }


    // Chuyển Document thành XML string
    public void toXMLString() throws TransformerException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");

        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(this.document), new StreamResult(writer));
    }
}