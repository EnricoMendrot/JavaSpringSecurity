package local.enrico.SecurityJwt.security.jwt;

import local.enrico.SecurityJwt.security.entites.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.lang.System.Logger;
import java.util.Base64;
import java.util.Date;
import javax.crypto.SecretKey;
import org.junit.platform.commons.logging.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 *
 * @author Enrico
 */
@Component
public class JwtTokenUtil {
    
    /**
     * Serve para definir o tempo de expiração em 24 horas, mas em milisesimos
     */
    private static final long EXPIRE_DURATION = 24 * 60 * 60 * 1000;
    
    /**
     * @Value serve para injetar o que ta no parênteses na variável.
     */
    @Value("${app.jwt.secret}")
    private String SECRET_KEY;
   
    /**
    * O Logger serve para gravar mensagens que pode ser usadas para gravar erros, avisos e informações 
    * JwtTokenUtil.class serve para ser o local em que vai ser salva a mensagem
    */ 
    private static final Logger LOGGER = (Logger) LoggerFactory.getLogger(JwtTokenUtil.class);
    
    // ============================ GERAR O TOKEN ============================//
    /**
     * Criar um token JWT para um usuário, assinado com uma chave secreta, que inclui ID, e-mail e tempo de expiração.  
     * @param user objeto da classe User em br.eti.kge.SecurityJwt.security.entites.
     * @return constroi o Jwts
     */
    public String generateAccessToken(User user) {
        // Decodifica a sua chave secreta (que está codificada em Base64 no seu application.properties)
        byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY);
        // Cria uma chave segura (secretKey) para usar na assinatura do token.
        SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);
            return Jwts.builder()
        // Defini o id e o email, os quais são do dono do token
        .setSubject(String.format("%s,%s", user.getId(), user.getEmail()))
        // Define quem criou o token
        .setIssuer("EnricoMendrot")
        // Define a data da criação do token
        .setIssuedAt(new Date())
        // Define o tempo de expiração (24 horas)
        .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_DURATION))
        // Entra com a chave secreta usando o algoritmo HS512
        .signWith(secretKey, SignatureAlgorithm.HS512)
        // Finaliza e transforma tudo isso num token JWT pronto pra uso       
        .compact();
    }
    
    // =========================== VALIDAR O TOKEN ===========================//
    /**
     * Esse método tenta decodificar e verificar o token.
       Se conseguir → é válido.
       Se falhar → ele sabe exatamente por que falhou.
     * @param token representa o token
     * @return 
     */
    public boolean validateAccessToken(String token) {
        try {
            // Responsável por decodificar a chave secreta
            byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY);
            // Cria uma chave segura (secretKey) para usar na assinatura do token.
            SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);
            // Verifica a assinatura digital; Verifica se o token está correto e íntegro; Verifica se ele ainda não expirou
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
            
          // O token já expirou
        } catch (ExpiredJwtException ex) {
            LOGGER.error("JWT expired", ex.getMessage());
         // O token não está presente
        } catch (IllegalArgumentException ex) {
            LOGGER.error("Token is null, empty or only whitespace", ex.getMessage());
         // Token mal informado
        } catch (MalformedJwtException ex) {
            LOGGER.error("JWT is invalid", ex);
         // O token está em formato errado
        } catch (UnsupportedJwtException ex) {
            LOGGER.error("JWT is not supported", ex);
         // A assinatura foi alterada
        } catch (SignatureException ex) {
            LOGGER.error("Signature validation failed");
        }
        return false;
    }
    
    /**
     * Pega quem é o dono do token 
     * @param token
     * @return 
     */
    public String getSubject(String token) {
        return parseClaims(token).getSubject();
    }
    
    private Claims parseClaims(String token) {
        byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY);
        SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);
        return Jwts.parserBuilder()
        // Valida e decodifica o token JWT
        .setSigningKey(secretKey).build()
        // Pega o corpo do token, que são os dados úteis
        .parseClaimsJws(token)
        .getBody();
    }
}
