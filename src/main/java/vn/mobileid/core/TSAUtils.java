package vn.mobileid.core;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;

public class TSAUtils {

    private static final String TSA_URL = "http://ca.gov.vn/tsa"; // URL TSA thực tế

    public static byte[] getTimeStampToken(byte[] dataToHash) {
        try {
            // 1. Băm dữ liệu đầu vào bằng SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dataToHash);

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier(TSPAlgorithms.SHA256.getId()));

// Tạo MessageImprint với AlgorithmIdentifier
            MessageImprint messageImprint = new MessageImprint(algorithmIdentifier, hash);

            TimeStampReq timeStampReq = new TimeStampReq(
                    messageImprint, null, null, null, null);

            // 3. Gửi TimeStampReq tới TSA
            byte[] requestBytes = timeStampReq.getEncoded();
            byte[] responseBytes = sendRequestToTSA(requestBytes);

            // 4. Xử lý TimeStampResp
            TimeStampResp timeStampResp = TimeStampResp.getInstance(responseBytes);

            // Kiểm tra trạng thái phản hồi và trích xuất token
            if (timeStampResp.getTimeStampToken() != null) {
                System.out.println("TimeStampToken nhận thành công từ TSA.");
                return timeStampResp.getTimeStampToken().getEncoded();
            } else {
                System.err.println("Phản hồi từ TSA không có TimeStampToken.");
                return null;
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Gửi TimeStampReq đến TSA và nhận TimeStampResp
    private static byte[] sendRequestToTSA(byte[] requestBytes) throws IOException {
        URL url = new URL(TSA_URL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        // Cấu hình kết nối HTTP
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/timestamp-query");

        // Gửi TimeStampReq
        try (OutputStream os = connection.getOutputStream()) {
            os.write(requestBytes);
        }

        // Nhận TimeStampResp
        try (InputStream is = connection.getInputStream()) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int bytesRead;
            byte[] data = new byte[1024];
            while ((bytesRead = is.read(data)) != -1) {
                buffer.write(data, 0, bytesRead);
            }
            return buffer.toByteArray();
        }
    }
}
