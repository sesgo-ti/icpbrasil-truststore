# Como o acervo é gravado

Vale para o [diretório local](armazenamento-filesystem.md) e para o [S3](armazenamento-s3.md).

## Estrutura

```
hash.txt                    ← aponta para a geração vigente
geracoes/<hash>/            ← uma pasta por versão do acervo (ZIP e data da última confirmação)
```

## Garantias

- **Escrita segura:** cada arquivo é gravado num temporário e só então movido para o lugar. O
  ponteiro `hash.txt` é trocado por último. Se o processo cair no meio (disco cheio, reinício), a
  geração anterior continua vigente e completa.
- **Várias instâncias:** podem compartilhar o mesmo diretório ou bucket. As gerações não mudam
  depois de gravadas, e cada instância confere o SHA-512 do ZIP ao carregar.
- **Limpeza automática:** gerações que não são a vigente nem a anterior, e temporários
  abandonados, são apagados depois de 24 h sem mudança.
- **Migração:** o formato da versão 0.0.1 é lido e convertido automaticamente, sem novo download.
