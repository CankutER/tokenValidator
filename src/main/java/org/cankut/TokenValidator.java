package org.cankut;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;


public class TokenValidator {

    private String providerUrl="https://login.microsoftonline.com/5203410c-2bf1-4f20-84ff-c70f1298bcc3/discovery/v2.0/keys";
    private RSAPublicKey getPublicKey(DecodedJWT jwt) throws JwkException, MalformedURLException {
        JwkProvider provider= new UrlJwkProvider(new URL(providerUrl));
        return (RSAPublicKey) provider.get(jwt.getKeyId()).getPublicKey();

    }
    public String validate(String token)  {
        boolean isValid=true;

        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            RSAPublicKey publicKey = getPublicKey(decodedJWT);
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(decodedJWT.getIssuer())
                    .build();

            verifier.verify(token);
        }
            catch (Exception err){
                System.out.println(err.getMessage());
                isValid=false;
            }



        return isValid + " and "+ token;
    }
}
