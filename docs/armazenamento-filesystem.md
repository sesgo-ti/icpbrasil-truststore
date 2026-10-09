# Quero gravar o acervo num diretório local

O acervo de ACs baixado do ITI é gravado num diretório do disco. É o armazenamento padrão.

## 1. Configure o diretório

No `application.yml`:

```yaml
icpbrasil-truststore:
  filesystem:
    base-dir: /var/lib/minha-app/icpbrasil-truststore
```

No serviço REST, passe na linha de comando: `--icpbrasil-truststore.filesystem.base-dir=/data/truststore`.

`base-dir` é obrigatória: sem ela, a aplicação não sobe. O diretório é criado se não existir.

## 2. Garanta a persistência

- O usuário da aplicação precisa de permissão de escrita no diretório.
- Em contêiner, monte o diretório num volume. Sem volume, o acervo é baixado de novo a cada
  reinício.

## Veja também

- [Como o acervo é gravado](armazenamento-funcionamento.md): estrutura e uso por várias instâncias
- [Armazenamento no S3](armazenamento-s3.md)
