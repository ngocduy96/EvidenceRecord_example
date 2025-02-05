package vn.mobile.id.services;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

public interface SignatureService {

    String signDocument(String filePath) throws Exception;

    String timestampDocument(String filePath) throws Exception;

    String extendLTA(String filePath) throws Exception;

    DSSDocument renewalTimestamp(DSSDocument document) throws Exception;

    Reports validateDocument(DSSDocument document) throws Exception;

    default String saveSignedDocument(DSSDocument signedDocument, Path originalPath) throws Exception {
        // Lấy thư mục chứa file gốc, nếu null thì dùng thư mục hiện tại
        String parentDir = (originalPath.getParent() != null) ? originalPath.getParent().toString() : ".";

        // Định nghĩa tên file đã ký
        String signedFileName = "signed_" + originalPath.getFileName().toString();
        Path signedFilePath = Paths.get(parentDir, signedFileName);

        // Ghi file đã ký
        try (OutputStream os = new FileOutputStream(signedFilePath.toFile())) {
            signedDocument.writeTo(os);
        }
        return signedFilePath.toAbsolutePath().toString();
    }
}