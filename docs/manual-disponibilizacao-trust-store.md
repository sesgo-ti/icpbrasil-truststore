# Disponibilizar o serviço Trust Store

## Objetivo
Descrever o procedimento para disponibilizar o serviço Trust Store, fornecedor dos certificados confiáveis das Autoridades Certificadoras (ACs) que compõem o ecossistema ICP-Brasil.

## Pré-requisitos
- JDK 21
- Acesso ao MinIO (credenciais de adição e leitura de objetos em um bucket específico).
- Acesso ao Vault (credenciais de leitura de segredos).

## Procedimento

1. **Configure o projeto**
    No arquivo [application.yaml](../src/main/resources/application.yaml), configure as propriedades de acesso ao MinIO e ao Vault.

2. **Executar os testes automatizados**
    Execute os testes automatizados para garantir o bom funcionamento do serviço e a correta integração com o MinIO e o Vault:
    
    ```bash
    mvn clean test
    ```
   
3. **Construir o artefato**
    Construa o artefato JAR do serviço:

    ```bash
    mvn clean package
    ```
   
4. **Executar a aplicação**
    Antes de executar é preciso criar o truststore customizado da aplicação contendo o certificado SSL do Vault, conforme descrito no [Manual de Configuração do Certificado Vault](manual-configuracao-certificado-vault.md).

    ```bash
    java -Djavax.net.ssl.trustStore=path/to/mytruststore.jks -Djavax.net.ssl.trustStorePassword=changeit -jar target/trust-store-service.jar
    ```
