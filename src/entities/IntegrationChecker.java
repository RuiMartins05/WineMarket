package entities;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class IntegrationChecker {

    private SecretKeySpec keySpec;
    private byte[] previousHmac;

    public IntegrationChecker(String secretKey) {
        this.keySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        this.previousHmac = null;
    }

    public boolean beforeVsNowIntegrity(File file) throws Exception {
        byte[] currentHmac = calculateHmac(file);
        boolean isIntegrityValid = false;
        
        if (previousHmac != null && MessageDigest.isEqual(previousHmac, currentHmac)) {
            isIntegrityValid = true;
        } else {
            previousHmac = currentHmac;
        }
        
        return isIntegrityValid;
    }

    private byte[] calculateHmac(File file) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(keySpec);

        try (BufferedInputStream b = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buffer = new byte[1024];
            int r = b.read(buffer);
            while (r != -1) {
                hmac.update(buffer, 0, r);
                r = b.read(buffer);
            }
        }

        return hmac.doFinal();
    }

}

