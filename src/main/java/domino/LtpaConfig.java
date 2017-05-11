package domino;

public class LtpaConfig {
	public String	ltpaSecret;
	public String	tokenDomain;
	public String	dominohost;
	public int	tokenExpiration;
	public LtpaConfig() {
		ltpaSecret = "123456";
		dominohost = "";
		tokenDomain = ".gitsea.com";
		tokenExpiration = 86400;
	}	
}
