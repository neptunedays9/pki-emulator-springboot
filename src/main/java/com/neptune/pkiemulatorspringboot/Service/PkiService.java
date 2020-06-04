package com.neptune.pkiemulatorspringboot.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import com.neptune.pkiemulatorspringboot.Model.CsrModel;
import com.neptune.pkiemulatorspringboot.Model.JwtResponse;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;


import javax.security.auth.x500.X500Principal;

public class PkiService {

    public static Key key = null;
    public static KeyPair keypair = null;

    ObjectMapper mapper = new ObjectMapper();

    public String GenerateCSR() {
        String jws = null;
        try {
            if (keypair == null) {
                keypair = Keys.keyPairFor(SignatureAlgorithm.RS256);
            }

            RSAPublicKey rsaPub = (RSAPublicKey) keypair.getPublic();
            CsrModel csrModel = new CsrModel();
            csrModel.certificate = Base64.getEncoder().encodeToString(rsaPub.getEncoded());

            X500Principal principal = new X500Principal("CN=");

            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    principal,
                    keypair.getPublic()
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keypair.getPrivate());

            PKCS10CertificationRequest pkcs10 = p10Builder.build(signer);

            String str = Base64.getEncoder().encodeToString(pkcs10.getEncoded());
            csrModel.csr = str;

            String jwtTokenString = mapper.writeValueAsString(csrModel);
            jws = Jwts.builder().setPayload(jwtTokenString).signWith(keypair.getPrivate()).compact();


        } catch (OperatorCreationException | IOException e) {
            e.printStackTrace();
        }

        return jws;
    }

    public String GenerateJwt(String payload) throws JsonProcessingException {
        String jwt = null;
        if (keypair == null) {
            keypair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        }

        String jwtTokenString = mapper.writeValueAsString(payload);
        jwt = Jwts.builder().setPayload(jwtTokenString).signWith(keypair.getPrivate()).compact();

        return jwt;
    }
}
