package com.xue.resourceserver.contrl;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Xuewu
 * @date 2019/2/20
 */
@RestController
public class IndexController {

    @GetMapping("/index")
    @ResponseBody
    public String index(){
        return "welcome";
    }

}
