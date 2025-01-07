package com.catalystone.sas.sasnua.controllers;


import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Arrays;
import java.util.List;

@Controller
@RequestMapping("/oauth2/consent") @Slf4j
public class ConsentController {

    @GetMapping
    public String consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state,
                          @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) String userCode, HttpServletRequest request) {
        // Fetch application details based on client_id (replace with your logic)
        String applicationName = "CO Authorization Server";
        // Example: Fetch from database
        // Parse scope string into a list
        log.info("Request Principal: {}", request.getSession().getAttribute("principal"));
        var act = (OAuth2AuthorizationCodeRequestAuthenticationToken) request.getSession().getAttribute("newOAuth2Req");
        log.info("tenant auth req id : {} " , act.getAdditionalParameters().get("tenantAuthReqId"));

        log.info("Principal: {}", principal);
        List<String> scopes = Arrays.asList(scope.split(" "));
        model.addAttribute("application", applicationName);
        model.addAttribute("scopes", scopes);
        model.addAttribute("clientId", clientId);
        model.addAttribute("redirectUri", "redirectUri");
        model.addAttribute("state", state);
        model.addAttribute("tenantAuthReqId",  act.getAdditionalParameters().get("tenantAuthReqId"));

        return "consent"; // Return the name of your Thymeleaf template
    }
}
