package vn.mobileid.utils;

import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;

import java.io.FileOutputStream;
import java.io.IOException;

public class Utils {
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
}
