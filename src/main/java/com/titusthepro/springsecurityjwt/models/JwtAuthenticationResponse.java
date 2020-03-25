package com.titusthepro.springsecurityjwt.models;

public class JwtAuthenticationResponse {
    /*
     * Needed for jwt token. Like needed for the output
     */
    private final String JWT;

    public JwtAuthenticationResponse(String jwt) {
        this.JWT = jwt;
    }

    public String getJWT() {
        return JWT;
    }
}
