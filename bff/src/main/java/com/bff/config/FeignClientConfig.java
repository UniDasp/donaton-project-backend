package com.bff.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import jakarta.servlet.http.HttpServletRequest;
import feign.RequestInterceptor;
import lombok.extern.slf4j.Slf4j;

/**
 * Interceptor de OpenFeign para propagar headers de identidad.
 * 
 * PATRÓN: Seguridad Perimetral
 * 
 * El Gateway inyecta los headers X-User-Email y X-User-Role en la petición entrante.
 * El BFF debe clonar esos headers en todas las llamadas a OpenFeign hacia los microservicios core.
 * 
 * Esto se logra leyendo el RequestContext de la petición HTTP actual
 * y copiando los headers a la plantilla de Feign.
 */
@Slf4j
@Configuration
public class FeignClientConfig {

    /**
     * Crea un RequestInterceptor que clona los headers de identidad.
     * 
     * Flujo:
     * 1. Lee los headers de la petición HTTP actual: Authorization, X-User-Email, X-User-Role
     * 2. Los copia a la plantilla de OpenFeign
     * 3. Feign reutiliza esos headers en llamadas síncronas a microservicios
     * 
     * El RequestContextHolder es stateless y está disponible automáticamente en Spring Web.
     * No requiere Spring Security ni configuraciones de autenticación.
     */
    @Bean
    public RequestInterceptor feignAuthRequestInterceptor() {
        return template -> {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();

                // Leer headers inyectados por el Gateway
                String authHeader = request.getHeader("Authorization");
                String userEmail = request.getHeader("X-User-Email");
                String userRole = request.getHeader("X-User-Role");

                // Clonar headers a la plantilla de Feign
                if (authHeader != null && !authHeader.isBlank()) {
                    template.header("Authorization", authHeader);
                    log.debug("[FEIGN-INTERCEPTOR] Propagando Authorization header");
                }
                if (userEmail != null && !userEmail.isBlank()) {
                    template.header("X-User-Email", userEmail);
                    log.debug("[FEIGN-INTERCEPTOR] Propagando X-User-Email: {}", userEmail);
                }
                if (userRole != null && !userRole.isBlank()) {
                    template.header("X-User-Role", userRole);
                    log.debug("[FEIGN-INTERCEPTOR] Propagando X-User-Role: {}", userRole);
                }
            } else {
                log.warn("[FEIGN-INTERCEPTOR] RequestAttributes no disponible - sin headers para propagar");
            }
        };
    }
}