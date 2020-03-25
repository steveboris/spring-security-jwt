/**
 *  Accepts user Id and Password than return JWT as response
 */
package com.titusthepro.springsecurityjwt.controller;

import com.titusthepro.springsecurityjwt.config.JwtTokenUtil;
import com.titusthepro.springsecurityjwt.models.JwtAuthenticationRequest;
import com.titusthepro.springsecurityjwt.models.JwtAuthenticationResponse;
import com.titusthepro.springsecurityjwt.services.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = {"/authenticate"}, method = RequestMethod.POST)
public class JwtAuthenticate {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @GetMapping
    @ResponseBody
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtAuthenticationRequest jwtAuthenticationRequest) throws Exception {

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(jwtAuthenticationRequest.getUsername(), jwtAuthenticationRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect Username or Passeword", e);
        }

        // get userDetails
        final UserDetails userDetails = myUserDetailsService.loadUserByUsername(jwtAuthenticationRequest.getUsername());

        // generate the output
        final String jwt = jwtTokenUtil.generateToken(userDetails);

        // creata a authentication response
        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
    }
}
