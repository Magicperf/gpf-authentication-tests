package digital.gartner.common;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;
import org.testng.Assert;

public class AuthenticationTest {
    @Test
    public void test() throws Exception {
        assertTrue(true);
    }
    
    @Test
    public void generatePasswordTokenTest() {
    	Authentication a = new Authentication();
    	String username = "a";
    	String password = "b";
    	String nonce = "d";
    	String url = "c";
    	
    	String result = a.generatePasswordToken(url, username, password, nonce);
    	String passwordHash = a.generatePasswordHash(username, password);
    	String payload = url + passwordHash + username + nonce;
    	Assert.assertEquals(result,HmacUtils.hmacSha256Hex(passwordHash, payload));
    }
    
    @Test
    public void generatePasswordHashTest() {
    	Authentication a = new Authentication();
    	String username = "a";
    	String password = "b";
    	String result = a.generatePasswordHash(username, password);
    	
    	Assert.assertEquals(result, DigestUtils.sha256Hex(username + ":" + password));
    }
    
    @Test
    public void generateSignatureGoodTest() {
    	Authentication a = new Authentication();
    	String payload = "a";
    	String timestamp = "b";
    	String publicKey = "c";
    	String nonce = "d";
    	String accessToken = "e";
    	String result = a.generateSignature(payload, publicKey, nonce, timestamp, accessToken);
    	
    	StringBuilder buf = new StringBuilder();
    	
        buf.append(payload)
                .append(timestamp)
                .append(publicKey)
                .append(nonce);
        Assert.assertEquals(result, HmacUtils.hmacSha256Hex(accessToken, buf.toString()));
    }
    
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest() throws Exception{
    	Authentication a = new Authentication();
    	String result = a.generateSignature(null, "", "", "", "");
    	
    	fail();
    }
    
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest2() throws Exception{
    	Authentication a = new Authentication();
    	String result = a.generateSignature("", null, "", "", "");
    	
    	fail();
    }
    
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest3() throws Exception{
    	Authentication a = new Authentication();
    	String result = a.generateSignature("", "", null, "", "");
    	
    	fail();
    }
    
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest4() throws Exception{
    	Authentication a = new Authentication();
    	String result = a.generateSignature("", "", "", null, "");
    	
    	fail();
    }
    
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateSignatureTest5() throws Exception{
    	Authentication a = new Authentication();
    	String result = a.generateSignature("", "", "", "", null);
    	
    	fail();
    }
    
    @Test
    public void generateAccessTokenGoodTest() {
    	Authentication a = new Authentication();
    	String publicId = "test";
    	String secretKey = "test";
    	String timestamp = "test";
    	
    	String result = a.generateAccessToken(publicId, secretKey, timestamp);
    	Assert.assertNotEquals(result, publicId);
    	Assert.assertNotEquals(result, secretKey);
    	Assert.assertNotEquals(result, timestamp);
    	
    	StringBuilder buf = new StringBuilder();

        buf.append(publicId)
                .append(secretKey)
                .append(timestamp);
        
    	Assert.assertEquals(result, HmacUtils.hmacSha256Hex(secretKey, buf.toString()));
    }
    
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateAccessTokenTest() throws Exception{
    	Authentication a = new Authentication();
    	String result = a.generateAccessToken(null, "", "");
    	fail();
    }
    
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateAccessTokenTest2() throws Exception{
    	Authentication a = new Authentication();
    	String result = a.generateAccessToken("", null, "");
    	fail();
    }
    
    @Test(expectedExceptions= {Exception.class,RuntimeException.class})
    public void generateAccessTokenTest3() throws Exception{
    	Authentication a = new Authentication();
    	String result = a.generateAccessToken("", "", null);
    	fail();
    }
}