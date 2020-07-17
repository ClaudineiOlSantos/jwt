import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Classe para geração de token JWT
 * 
 * Usado como referência o artigo: https://metamug.com/article/security/jwt-java-tutorial-create-verify.html
 * Porém simplificando algumas coisas.
 * 
 * Esta classe depende do pacote org.json
 * 
 * @author Claudinei
 * @email claudineioliveirasa@live.com
 */
public class JWebToken {

	public static Protocol protocol=Protocol.HS512;
    private static final String SECRET_KEY = "manual-wordpress";
    private static final int EXPIRY_DAYS = 90;
    private static final String JWT_HEADER = "{\"alg\":\""+protocol.name()+"\",\"typ\":\"JWT\"}";
    private JSONObject payload = new JSONObject();
    private String signature;
    private String encodedHeader;

    private JWebToken() throws JSONException {
        encodedHeader = encode(new JSONObject(JWT_HEADER));
    }


    public JWebToken(String sub, String name ) throws JSONException {
        this();
        payload.put("sub", sub);
        payload.put("name", name);       
        payload.put("exp", LocalDateTime.now().plusDays(EXPIRY_DAYS).toEpochSecond(ZoneOffset.UTC));
        //payload.put("iat", LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
        //payload.put("jti", UUID.randomUUID().toString()); //how do we use this?
       
        signature = hmacSha(encodedHeader + "." + encode(payload), SECRET_KEY);        
    }

    /**
     * For verification
     *
     * @param token
     * @throws java.security.NoSuchAlgorithmException
     * @throws JSONException 
     */
    public JWebToken(String token) throws NoSuchAlgorithmException, JSONException {
        this();
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid Token format");
        }
        if (encodedHeader.equals(parts[0])) {
            encodedHeader = parts[0];
        } else {
            throw new NoSuchAlgorithmException("JWT Header is Incorrect: " + parts[0]);
        }

        payload = new JSONObject(decode(parts[1]));
        if (payload == null) {
            throw new JSONException("Payload is Empty: ");
        }
        if (!payload.has("exp")) {
            throw new JSONException("Payload doesn't contain expiry " + payload);
        }
        signature = parts[2];
    }

    @Override
    public String toString() {
        return encodedHeader + "." + encode(payload) + "." + signature;
    }

    public boolean isValid() throws JSONException {
        return payload.getLong("exp") > (LocalDateTime.now().toEpochSecond(ZoneOffset.UTC)) //token not expired
                && signature.equals(hmacSha(encodedHeader + "." + encode(payload), SECRET_KEY)); //signature matched
    }

    public String getSubject() throws JSONException {
        return payload.getString("sub");
    }
    
    public String getName() throws JSONException {
        return payload.getString("name");
    }


    private static String encode(JSONObject obj) {
        return encode(obj.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String decode(String encodedString) {
        return new String(Base64.getUrlDecoder().decode(encodedString));
    }

    /**
     * Sign with HMAC SHA256 (HS256)
     *
     * @param data
     * @return
     * @throws Exception
     */
    private String hmacSha(String data, String secret) {
        try {
            
            byte[] hash = secret.getBytes(StandardCharsets.UTF_8);
           
            Mac sha256Hmac = Mac.getInstance(protocol.label);
            SecretKeySpec secretKey = new SecretKeySpec(hash, protocol.label);
            sha256Hmac.init(secretKey);

            byte[] signedBytes = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return encode(signedBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            Logger.getLogger(JWebToken.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return null;
        }
    }
    
   

}

/**
 * Protocolo de criptografia suportados
 * @author diney
 *
 */
enum Protocol{
	HS256("HmacSHA256"),HS512("HmacSHA512");
	
	public final String label;
	
	Protocol(String label){
		this.label=label;
	}
}
