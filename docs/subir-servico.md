# Quero subir o serviço REST

O serviço mantém o acervo de ACs vigentes da ICP-Brasil e o serve por SKI via HTTP.

## Pré-requisitos

- Java 21.
- Liberar as [saídas de rede](seguranca.md#saídas-de-rede-necessárias).

## 1. Obtenha o executável

Baixe `icpbrasil-truststore-rest-<versão>.jar` da
[GitHub Release](https://github.com/sesgo-ti/icpbrasil-truststore/releases) e
[confira o checksum](verificar-artefatos.md#executável-do-serviço-github-release).

Ou gere a partir do código (o JAR sai em `icpbrasil-truststore-rest/target/`):

```bash
./mvnw clean package -DskipTests
```

## 2. Escolha onde gravar o acervo

- [Diretório local](armazenamento-filesystem.md) (padrão)
- [S3](armazenamento-s3.md)

## 3. Execute

```bash
java -jar icpbrasil-truststore-rest-<versão>.jar --icpbrasil-truststore.filesystem.base-dir=/data/truststore
```

A porta padrão é `8080` (mude com `--server.port`).

Na primeira subida, o serviço baixa o acervo do ITI; se o download falhar, o processo encerra com
erro. Nas seguintes, reaproveita o acervo gravado e sobe na hora.

## 4. Verifique

```bash
curl http://localhost:8080/actuator/health/readiness
```

`UP` indica acervo carregado. Até lá, `/certificate` responde 503.

## Veja também

- [Endpoints REST](endpoints-rest.md)
- [Monitoramento](monitorar.md)
- [Referência de configuração](configuracao.md)
