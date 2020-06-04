package com.neptune.pkiemulatorspringboot.Controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.neptune.pkiemulatorspringboot.Model.CsrJwtResponse;
import com.neptune.pkiemulatorspringboot.Model.JwtResponse;
import com.neptune.pkiemulatorspringboot.Service.PkiService;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping("api/v1")
public class PkiController {
    PkiService pkiService;

    @RequestMapping("csr")
    public CsrJwtResponse GetCSR() {
        String jws = pkiService.GenerateCSR();
        CsrJwtResponse jwtResponse = new CsrJwtResponse();
        jwtResponse.token = jws;

        return jwtResponse;
    }

    @RequestMapping("jwt")
    public JwtResponse GetDigitalCertificate(String payload) throws JsonProcessingException {
        String token = pkiService.GenerateJwt(payload);
        JwtResponse jwt = new JwtResponse();
        jwt.token = token;
        return null;
    }
}
