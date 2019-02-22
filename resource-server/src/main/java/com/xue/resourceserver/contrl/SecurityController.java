package com.xue.resourceserver.contrl;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Xuewu
 * @date 2019/2/20
 */
@RestController
public class SecurityController {

    @GetMapping("/sc/boss")
    @ResponseBody
    @PreAuthorize("hasAnyAuthority('A', 'B')")
    public String sc(OAuth2Authentication auth) {
        SecurityContext context = SecurityContextHolder.getContext();
        Object principal = context.getAuthentication().getPrincipal();
        return "boss";
    }
}
