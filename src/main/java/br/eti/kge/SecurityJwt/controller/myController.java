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
 * @author Enrico Mendrot
 */

@RestController
@RequestMapping("/")
public class myController {

    /**
     * É feito para que cada um tenha um identificador unico, ou seja,
     * restringindo a permissão para cada um
     * @return vai retornar o model, cujo está com as informações de 'id' e de token. Além disso, caso o usuario não tenha permissão vai ser mostrado a permissão
     * @HashMap é um identificador unico que não pode existir outro igual
     */
    
    // Apenas ADMIN pode ter acesso.
    @GetMapping("/manager")
    public Map<String, Object> privateManageEndpoint() {
        Map<String, Object> model = new HashMap<String, Object>();
        /**
         * @UUID.randomUUID().toString() Responsável por criar um identificador único automaticamente.
         */
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
