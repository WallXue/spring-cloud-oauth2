package com.xue.resourceserver.contrl;

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
    public String sc() {
        return "boss";
    }
}
