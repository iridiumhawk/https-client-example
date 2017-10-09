package io.packagecloud.https_client_example;

import org.testng.annotations.Test;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.*;

public class HttpsTest {
    @Test
    public void testTwoWayAuthentication() throws IOException {

        URL url = new URL("https://google.com/");

        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setRequestMethod("GET");
//        con.connect();

        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("TLS");//TLS
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        char[] passphrase = "storepass".toCharArray();
        char[] keypass = "serverpass".toCharArray();

     /*   KeyStore ks = null;
        KeyManagerFactory kmf= null;
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(this.getClass().getResourceAsStream("client.jks"), passphrase);

            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, keypass);

            System.out.println(kmf.getAlgorithm());
            System.out.println(ks.getProvider());

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }

*/
        KeyStore ts = null;
        TrustManagerFactory tmf = null;
        try {
            ts = KeyStore.getInstance("JKS");
            ts.load(this.getClass().getResourceAsStream("clienttrust.jks"), passphrase);
            //c:\java\projects\https-client-blog-example\src\test\resources\
            tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);


            System.out.println(tmf.getAlgorithm());
            System.out.println(ts.getProvider());

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        HostnameVerifier hostnameVerifier = new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return s.equals(sslSession.getPeerHost());
            }
        };
        con.setHostnameVerifier(hostnameVerifier);


        try {
            sslContext.init(null, null, null);
//            sslContext.init(null, tmf.getTrustManagers(), null);

        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        con.setSSLSocketFactory(sslContext.getSocketFactory());

        int responseCode = con.getResponseCode();
        InputStream inputStream;
        if (responseCode == HttpURLConnection.HTTP_OK) {
            inputStream = con.getInputStream();
        } else {
            inputStream = con.getErrorStream();
        }

        // Process the response
        BufferedReader reader;
        String line = null;
        reader = new BufferedReader(new InputStreamReader(inputStream));
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }


        java.security.cert.Certificate[] serverCertificates = con.getServerCertificates();
        X509Certificate x509cert;
        for (java.security.cert.Certificate serverCertificate : serverCertificates) {
            x509cert = (X509Certificate) serverCertificate;
            System.out.println(x509cert.getIssuerX500Principal().getName());
            System.out.println(x509cert.toString());
        }

        inputStream.close();
    }
}
