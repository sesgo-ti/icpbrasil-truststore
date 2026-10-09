# Quero usar um diretório local como armazenamento

O acervo de ACs baixado do ITI é gravado num diretório do disco. É o armazenamento padrão.

## 1. Dependência

```xml
<dependency>
    <groupId>br.gov.go.saude</groupId>
    <artifactId>icpbrasil-truststore-spring-boot-starter</artifactId>
    <version>0.0.3</version>
</dependency>
```

Nenhuma outra dependência é necessária.

## 2. Configuração

No `application.yml`:

```yaml
icpbrasil-truststore:
  filesystem:
    base-dir: /var/lib/minha-app/icpbrasil-truststore
```

`base-dir` é a única propriedade obrigatória. Sem ela, a aplicação não sobe.

## 3. Pronto

Na subida, a biblioteca cria o diretório se ele não existir, baixa o acervo do ITI e carrega o cache.
Nas subidas seguintes, reaproveita o que já está no disco.

## Cuidados

- O usuário da aplicação precisa de permissão de escrita no diretório.
- Em contêiner, monte o diretório num volume. Sem volume, o acervo é baixado de novo a cada
  reinício.
- Várias instâncias podem usar o mesmo diretório (por exemplo, um volume compartilhado).

Como os arquivos são organizados: [como o acervo é gravado](armazenamento-funcionamento.md).
