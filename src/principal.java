import java.security.NoSuchAlgorithmException;
import org.json.JSONException;

public class principal {

	public static void main(String[] args) throws NoSuchAlgorithmException {

		try {

			String token = new JWebToken("John Doe", "1516239022").toString();

			System.out.println(token);

			// verify and use
			JWebToken incomingToken = new JWebToken(token);
			if (!incomingToken.isValid()) {				 
				System.out.println("N�o v�lido");
			} else {
				System.out.println("V�lido");
			}
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		;
	}

}
