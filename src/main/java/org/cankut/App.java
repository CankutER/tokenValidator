package org.cankut;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        String token ="empty token";
        TokenValidator validator =new TokenValidator();
        String result=validator.validate(token);
        System.out.println(result);

    }
}
