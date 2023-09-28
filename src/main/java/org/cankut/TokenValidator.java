package org.cankut;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;


public class TokenValidator {

    private List<String> providerUrl =new ArrayList<String>();
    private List<String> auds=new ArrayList<String>();
    private List<String> issuers=new ArrayList<String>();


    TokenValidator(){
        providerUrl.add("https://login.microsoftonline.com/4582d001-8b21-4d86-a022-ed39854d1656/discovery/v2.0/keys");
        auds.add("api://e23d6e3d-fb99-42f4-87ca-c1a5db851d32");
        issuers.add("https://sts.windows.net/4582d001-8b21-4d86-a022-ed39854d1656/");
    }
    private RSAPublicKey getPublicKey(DecodedJWT jwt) throws JwkException, MalformedURLException {
        JwkProvider provider= new UrlJwkProvider(new URL(providerUrl.get(0)));
        return (RSAPublicKey) provider.get(jwt.getKeyId()).getPublicKey();

    }

    private List<String> getScopes(DecodedJWT decodedJWT){
        Map<String, Claim> claims=decodedJWT.getClaims();
        String scopeStr=claims.get("scp").asString();
         List<String> scopes= Arrays.asList(scopeStr.split(" "));
        System.out.println(scopes.get(0));
        return scopes;
    }

    private String getAud(DecodedJWT decodedJWT){
        Map<String, Claim> claims=decodedJWT.getClaims();
        String aud=claims.get("aud").asString();
        System.out.println(aud);
        return aud;

    }

    private String getIss(DecodedJWT decodedJWT){
        Map<String, Claim> claims=decodedJWT.getClaims();
        String iss=claims.get("iss").asString();
        System.out.println(iss);
        return iss;

    }

    private boolean checkClaims(DecodedJWT jwt){
        String aud=getAud(jwt);
        String iss=getIss(jwt);
        return issuers.contains(iss) && auds.contains(aud);

    }

    public String validate(String token)  {
        boolean isValid=true;
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            System.out.println(checkClaims(decodedJWT));
            List<String> scopes=getScopes(decodedJWT);
            RSAPublicKey publicKey = getPublicKey(decodedJWT);
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(decodedJWT.getIssuer())
                    .build();

            verifier.verify(token);
        }
            catch (Exception err){
            if (err instanceof JwkException || err instanceof JWTVerificationException){
                System.out.println(err.getMessage());
                isValid=false;
            }
            else {
                System.out.println(err.getMessage());
            }

        }


        return isValid + " and "+ token;
    }
}

