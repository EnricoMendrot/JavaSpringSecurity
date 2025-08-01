/*
* _  ______        _____ _   _   ____       
* | |/ / ___| ___  | ____| |_(_) | __ ) _ __ 
* | ' / |  _ / _ \ |  _| | __| | |  _ \| '__|
* | . \ |_| |  __/_| |___| |_| |_| |_) | |   
* |_|\_\____|\___(_)_____|\__|_(_)____/|_|   
*
 */
package br.eti.kge.SecurityJwt.controller;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller para demonstrar acesso public e acesso private em
 * endpoints no geral.
 *
 * @author KGe
 */
@RestController
@RequestMapping("/")
public class myController {

    // Apenas ADMIN pode ter acesso.
    @GetMapping("/manager")
    public Map<String, Object> privateManageEndpoint() {
        Map<String, Object> model = new HashMap<String, Object>();
        model.put("id", UUID.randomUUID().toString());
        model.put("content", "Manager Endpoint: Area Apenas para ADMINS!!!");
        return model;
    }
    
    // Apenas Logados podem ter acesso
    @GetMapping("/private")
    public Map<String, Object> privateEndpoint() {
        Map<String, Object> model = new HashMap<String, Object>();
        model.put("id", UUID.randomUUID().toString());
        model.put("content", "Private Endpoint: Area Restrita!");
        return model;
    }

    // Todos podem ter acesso
    @RequestMapping("/public")
    public Map<String, Object> publicEndpoint() {
        Map<String, Object> model = new HashMap<String, Object>();
        model.put("id", UUID.randomUUID().toString());
        model.put("content", "Public Endpoint: Area Publica!");
        return model;
    }

}
