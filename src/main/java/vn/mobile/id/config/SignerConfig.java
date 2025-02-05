package vn.mobile.id.config;

public class SignerConfig {
    private final String p12FilePath;
    private final String p12Password;
    private final String TSA_URL;

    public SignerConfig(String p12FilePath, String p12Password, String TSA_URL) {
        this.p12FilePath = p12FilePath;
        this.p12Password = p12Password;
        this.TSA_URL = TSA_URL;
    }

    public String getP12FilePath() {
        return p12FilePath;
    }

    public String getP12Password() {
        return p12Password;
    }

    public String getTSA_URL() {
        return TSA_URL;
    }
}