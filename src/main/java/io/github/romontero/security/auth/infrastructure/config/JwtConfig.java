package io.github.romontero.security.auth.infrastructure.config;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwtConfig {


    public static final String KEY_ID = "github-auth-key";

    @Bean
    public RSAKey getRsaKey() throws IOException {

        ClassPathResource privateResource = new ClassPathResource("keys/private.pem");

        ClassPathResource publicResource = new ClassPathResource("keys/public.pem");

        RSAPrivateKey privateKey;

        try (InputStream is = privateResource.getInputStream()){
            privateKey = RsaKeyConverters.pkcs8().convert(is);
        }

        RSAPublicKey publicKey;

        try (InputStream is = publicResource.getInputStream()){
            publicKey = RsaKeyConverters.x509().convert(is);
        }

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(KEY_ID)
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(RSAKey rsaKey){
        JWKSet jwkSet = new JWKSet(rsaKey);

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);

        return new NimbusJwtEncoder(jwkSource);
    }
}
