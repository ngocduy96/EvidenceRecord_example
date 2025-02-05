package vn.mobile.id.sources;

import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;

public class OnlineSources {

    private static final String TSA_URL = "http://ca.gov.vn/tsa";

    public static OnlineTSPSource onlineTSPSource() {
        OnlineTSPSource onlineTSPSource = new OnlineTSPSource(TSA_URL);
        onlineTSPSource.setDataLoader(new TimestampDataLoader());
        return onlineTSPSource;
    }

    public static OnlineCRLSource onlineCRLSource() {
        OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
        onlineCRLSource.setDataLoader(dataLoader());
        return onlineCRLSource;
    }

    public static OnlineOCSPSource ocspSource() {
        return new OnlineOCSPSource();
    }

    public static CommonsDataLoader dataLoader() {
        CommonsDataLoader dataLoader = new CommonsDataLoader();
        dataLoader.setProxyConfig(null);
        return dataLoader;
    }
}