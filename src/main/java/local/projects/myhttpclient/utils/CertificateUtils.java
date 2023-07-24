package local.projects.myhttpclient.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 *
 * @author darkflammeus
 * @see https://github.com/wso2-extensions/identity-x509-commons/blob/743a9a1852c4462d4b142dca1db81ea8fd764b74/components/validation/src/main/java/org/wso2/carbon/identity/x509Certificate/validation/CertificateValidationUtil.java
 */
public abstract class CertificateUtils {

    static final Logger logger = Logger.getLogger(CertificateUtils.class.getName());

    public static CertificateStatus getRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert,
            int retryCount, List<String> locations)
            throws Exception {

        OCSPReq request = generateOCSPRequest(issuerCert, peerCert.getSerialNumber());

        for (String serviceUrl : locations) {
            SingleResp[] responses;

            try {

                logger.log(Level.INFO, "Trying to get OCSP Response from :  {0}", serviceUrl);

                OCSPResp ocspResponse = getOCSPResponse(serviceUrl, request, retryCount);

                if (OCSPResponseStatus.SUCCESSFUL != ocspResponse.getStatus()) {
                    logger.log(Level.INFO, "OCSP Response is not successfully received.");

                    continue;
                }

                BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
                responses = (basicResponse == null) ? null : basicResponse.getResponses();

            } catch (Exception e) {
                logger.log(Level.WARNING, "Error while checking {}", serviceUrl);
                logger.log(Level.WARNING, e.getMessage());
                continue;
            }

            if (responses != null && responses.length == 1) {
                return getRevocationStatusFromOCSP(responses[0]);
            }
        }

        throw new Exception("Cant get Revocation Status from OCSP using any of the OCSP Urls "
                + "for certificate with serial num:" + peerCert.getSerialNumber());
    }

    private static OCSPResp getOCSPResponse(String serviceUrl, OCSPReq request, int retryCount)
            throws Exception {

        OCSPResp ocspResp = null;

        try {
            HttpPost httpPost = new HttpPost(serviceUrl);

            setRequestProperties(request.getEncoded(), httpPost);

            DefaultHttpClient httpClient = new DefaultHttpClient();

            HttpResponse httpResponse = httpClient.execute(httpPost);

            //Check errors in response:
            if (httpResponse.getStatusLine().getStatusCode() / 100 != 2) {
                throw new Exception("Error getting ocsp response."
                        + "Response code is " + httpResponse.getStatusLine().getStatusCode());
            }

            InputStream in = httpResponse.getEntity().getContent();

            ocspResp = new OCSPResp(in);
        } catch (IOException e) {
            if (retryCount == 0) {
                throw new Exception("Cannot get ocspResponse from url: " + serviceUrl, e);
            } else {
                logger.log(Level.INFO, "Cant reach URI: {0}. Retrying to connect - attempt {1}", new Object[]{serviceUrl, retryCount});
                getOCSPResponse(serviceUrl, request, --retryCount);
            }
        }
        return ocspResp;
    }

    private static void setRequestProperties(byte[] message, HttpPost httpPost) {

        httpPost.addHeader("Content-Type",
                "application/ocsp-request");
        httpPost.addHeader("Accept",
                "application/ocsp-response");

        httpPost.setEntity(new ByteArrayEntity(message, ContentType.create(CONTENT_TYPE)));
    }

    private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
            throws Exception {

        try {
            String providerName = "BC";
            Provider provider = (Provider) (Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")).
                    getDeclaredConstructor().newInstance();

            /*
            Provider provider =(Provider) (Class.forName
                        ("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider")).getDeclaredConstructor().
                        newInstance();
             */
            Security.addProvider(provider);

            byte[] issuerCertEnc = issuerCert.getEncoded();

            X509CertificateHolder certificateHolder = new X509CertificateHolder(issuerCertEnc);
            DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().
                    setProvider(providerName).build();

            // CertID structure is used to uniquely identify certificates that are the subject of
            // an OCSP request or response and has an ASN.1 definition. CertID structure is defined in RFC 2560
            CertificateID id = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), certificateHolder,
                    serialNumber);

            // basic request generation with nonce
            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(id);

            ///*
            // create details for nonce extension. The nonce extension is used to bind a request to a response to
            // prevent replay attacks. As the name implies, the nonce value is something that the client should only
            // use once within a reasonably small period.
            // create the request Extension
            Extensions reqExtensions = new Extensions(new Extension[]{
                new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(BigInteger.valueOf(System.currentTimeMillis()).toByteArray()))
            });
                        
            builder.setRequestExtensions(reqExtensions);

            //*/
            return builder.build();

        } catch (Exception e) {
            throw new Exception("Cannot generate OSCP Request with the given certificate with "
                    + "serial num: " + serialNumber, e);
        }
    }

    private static CertificateStatus getRevocationStatusFromOCSP(SingleResp resp) {
        return resp.getCertStatus();
    }

    public static List<String> getAIALocations(X509Certificate cert) throws Exception {

        List<String> ocspUrlList;
        byte[] aiaExtensionValue = getAiaExtensionValue(cert);

        if (aiaExtensionValue == null) {
            throw new Exception("Certificate with serial num: "
                    + cert.getSerialNumber() + " doesn't have Authority Information Access points");
        }

        AuthorityInformationAccess authorityInformationAccess = getAuthorityInformationAccess(aiaExtensionValue);
        ocspUrlList = getOcspUrlsFromAuthorityInfoAccess(authorityInformationAccess);

        if (ocspUrlList.isEmpty()) {
            throw new Exception("Cant get OCSP urls from certificate with serial num: "
                    + cert.getSerialNumber());
        }

        return ocspUrlList;
    }

    private static List<String> getOcspUrlsFromAuthorityInfoAccess(AuthorityInformationAccess authorityInformationAccess) {

        List<String> ocspUrlList = new ArrayList<>();

        AccessDescription[] accessDescriptions;

        if (authorityInformationAccess != null) {
            accessDescriptions = authorityInformationAccess.getAccessDescriptions();

            for (AccessDescription accessDescription : accessDescriptions) {

                if (X509ObjectIdentifiers.ocspAccessMethod.equals(accessDescription.getAccessMethod())) {
                    GeneralName gn = accessDescription.getAccessLocation();

                    if (gn != null && gn.getTagNo() == GeneralName.uniformResourceIdentifier) {

                        var str = DERIA5String.getInstance(gn.getName());
                        String accessLocation = str.getString();
                        ocspUrlList.add(accessLocation);
                    }
                }
            }
        }
        return ocspUrlList;
    }

    private static AuthorityInformationAccess getAuthorityInformationAccess(byte[] aiaExtensionValue)
            throws Exception {

        AuthorityInformationAccess authorityInformationAccess;

        try {
            DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(aiaExtensionValue))
                    .readObject());
            authorityInformationAccess = AuthorityInformationAccess.getInstance(new ASN1InputStream(oct.getOctets())
                    .readObject());
        } catch (IOException e) {
            throw new Exception("Cannot read certificate to get OSCP urls", e);
        }

        return authorityInformationAccess;
    }

    private static byte[] getAiaExtensionValue(X509Certificate cert) {

        //Gets the DER-encoded OCTET string for the extension value for Authority information access Points
        return cert.getExtensionValue(Extension.authorityInfoAccess.getId());
    }
}
