package vn.mobileid.core;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.*;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class TSAUtils {

//        private static final String TSA_URL = "http://ca.gov.vn/tsa";
    private static final String TSA_URL = "https://freetsa.org/tsr";
//    private static final String TSA_URL = "http://timestamp.digicert.com";

    public static TimeStampResponse getTimeStampResponse(byte[] dataToHash) {
        try {

            byte[] responseBytes = sendRequestToTSA(dataToHash);

            TimeStampResponse timeStampResponse = new TimeStampResponse(responseBytes);

            if (timeStampResponse.getTimeStampToken() != null) {
                System.out.println("TimeStampToken nhận thành công từ TSA.");
                return timeStampResponse;
            } else {
                System.err.println("Phản hồi từ TSA không có TimeStampToken.");
                return null;
            }
        } catch (TSPException e) {
            System.err.println("Lỗi trong quá trình xử lý TimeStampResponse: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Lỗi trong việc gửi yêu cầu hoặc nhận phản hồi từ TSA: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Đã xảy ra lỗi: " + e.getMessage());
            e.printStackTrace();
        }

        return null;
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
