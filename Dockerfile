# Build Stage - Compilação da aplicação
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /app

# Copia arquivos de build
COPY pom.xml mvnw ./
COPY .mvn/ .mvn/
COPY src/ src/

# Baixa dependências
RUN chmod +x mvnw && ./mvnw dependency:go-offline -B

# Compila aplicação (sem testes, pois testes precisam de configuração específica)
RUN ./mvnw clean package -DskipTests

# Runtime Stage - Execução da aplicação
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Cria usuário não-root para segurança
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copia o JAR compilado
COPY --from=builder --chown=appuser:appgroup /app/target/*.jar app.jar

# IMPORTANTE: O truststore deve ser montado via volume ou copiado manualmente
# Não incluímos mytruststore.jks no build da imagem por segurança
# Veja docker-compose.yml para exemplo de como montar o arquivo

USER appuser
EXPOSE 8080

# Usa JAVA_OPTS do ambiente para configuração do truststore
# Permite flexibilidade na configuração sem rebuild da imagem
ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar app.jar"]