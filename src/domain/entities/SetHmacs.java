package domain.entities;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class SetHmacs implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    private Map<String, byte[]> mapHmac;

    public SetHmacs() {
        this.mapHmac = new HashMap<String, byte[]>();
    }

    public void setHmacPerFile(String file, byte[] hmac) {
        this.mapHmac.put(file, hmac);
    }

    public byte[] getMapHmac(String file) {
        return mapHmac.get(file);
    }

}