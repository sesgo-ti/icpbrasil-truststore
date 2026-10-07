# Disponibilizar o serviço Trust Store

## Objetivo

Colocar no ar o serviço REST (`icpbrasil-truststore-rest`), que mantém o acervo de Autoridades
Certificadoras vigentes da ICP-Brasil e o serve por SKI.

## Pré-requisitos

- JDK 21.
- Saída HTTPS para `acraiz.icpbrasil.gov.br` (download do acervo). Não é preciso configurar
  truststore na JVM: esse download usa um `SSLContext` próprio, com as âncoras embutidas (veja
  [gestão das âncoras TLS](manual-gestao-certificados-confiaveis.md)).
- Armazenamento persistente para o acervo: um diretório local ou um bucket S3-compatível
  (AWS S3, MinIO etc.) com permissão de leitura, escrita, listagem e remoção de objetos.

## Procedimento

1. **Obter o executável.** Baixe `icpbrasil-truststore-rest-<versão>.jar` e o `SHA256SUMS` da
   [GitHub Release](https://github.com/sesgo-ti/icpbrasil-truststore/releases) e confira:

    ```bash
    sha256sum -c SHA256SUMS --ignore-missing
    ```

    Ou construa a partir do código (o build é reproduzível: o mesmo commit gera o mesmo JAR):

    ```bash
    ./mvnw clean verify
    ```

2. **Configurar o armazenamento.** Filesystem (padrão):

    ```bash
    java -jar icpbrasil-truststore-rest-<versão>.jar \
      --icpbrasil-truststore.filesystem.base-dir=/data/truststore
    ```

    S3-compatível: defina `icpbrasil-truststore.storage.type=s3` e as variáveis `S3_ENDPOINT`,
    `S3_REGION`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET` e, só para endpoint com CA própria,
    `S3_CA_CERT_PATH` (veja o [README](../README.md#armazenamento-s3-compatível)). Várias
    instâncias podem compartilhar o mesmo diretório ou bucket (veja
    [layout do armazenamento](../README.md#layout-do-armazenamento)).

3. **Verificar.** A readiness só fica `UP` quando há acervo vigente:

    ```bash
    curl http://localhost:8080/actuator/health/readiness
    curl "http://localhost:8080/certificate?ski=<SKI>&type=pem"
    ```

    Estados do cache, logs e alertas: [manual de monitoramento](manual-monitoramento.md).
    Endpoints e parâmetros: [modo microserviço](exemplo-integracao-microservico.md).
