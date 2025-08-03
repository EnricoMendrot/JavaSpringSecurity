package local.enrico.SecurityJwt.security.jwt;

import local.enrico.SecurityJwt.security.entites.User;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 *
 * @author Enrico Mendrot
 */
// Essa classe é o porteiro do seu sistema:
// Toda requisição passa por ela, e ela decide se deixa entrar ou não.
@Component
public class JwtTokenFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtTokenUtil jwtUtil;
    
    @Override
    // Esse método é chamado automaticamente pelo Spring em toda requisição HTTP.
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
        throws ServletException, IOException {
            // Verifica se existe o Header
            if (!hasAuthorizationBearer(request)) {
                filterChain.doFilter(request, response);
                return;
        }
        // pega o token do cabeçalho
        String token = getAccessToken(request);
            // Valida o acesso do token (válido, não expirado e com a assinatura correta)
            if (!jwtUtil.validateAccessToken(token)) {
                filterChain.doFilter(request, response);
                return;
            }
        // Vai autenticar o usuario se o token estiver correto
        setAuthenticationContext(token, request);
        // A requisição continua o caminho (Controller)
        filterChain.doFilter(request, response);
    }
    
    /**
    * Verifica se existe um token Authorization que inicia com
    * a palavra "Bearer".
    *
    * @param request
    * @return
    */
    private boolean hasAuthorizationBearer(HttpServletRequest request) {
    String header = request.getHeader("Authorization");
    // Vai verificar se o header
    if (ObjectUtils.isEmpty(header) || !header.startsWith("Bearer")) {
        return false;
    }
        return true;
    }
    
    /**
    * Extrai o token do header Authentication
    *
    * @param request
    * @return
    */
    private String getAccessToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        /**
         * Vai dividir a String em pedaços;
         * O '1' pega a segunda parte, que é o token pura;
         * O trim tira as partes sem nada (" ")
         */
        String token = header.split(" ")[1].trim();
        return token;
    }
    
    // Esse método configura o usuário autenticado com base no token JWT, dentro do contexto de segurança do Spring.
    private void setAuthenticationContext(String token, HttpServletRequest request) {
        /** 
         * Pega os detalhes do usuario a partir do token
         * @param getUserDetails:
            Decodifica o token
            Extrai o ID ou o email
            Busca o usuário no banco
            Retorna um UserDetails com os dados dele
         */
        UserDetails userDetails = getUserDetails(token);
        /**
         * Cria o objeto de autentificação
         */
        UsernamePasswordAuthenticationToken authentication = new
        /**
         * Isso cria o objeto de autenticação com:
            O usuário (userDetails)
            As credenciais (null, porque já está autenticado por token)
            As autoridades (null, se você não estiver usando roles/perfis aqui)
         */
        UsernamePasswordAuthenticationToken(userDetails, null, null);
        // Defini novos detalhes
        authentication.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request));
        // Aqui é o ponto onde o Spring passa a considerar o usuário autenticado para essa requisição.
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    /**
     * Esse método extrai o ID e email do token e monta um objeto User com essas
     * informações para o Spring usar na autenticação.
     * @param token
     * @return 
     */ 
    private UserDetails getUserDetails(String token) {
        User userDetails = new User();
        String[] jwtSubject = jwtUtil.getSubject(token).split(",");
        userDetails.setId(Integer.parseInt(jwtSubject[0]));
        userDetails.setEmail(jwtSubject[1]);
        return userDetails;
    }
}
