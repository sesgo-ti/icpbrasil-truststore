# Contribuindo

Obrigado pelo interesse em contribuir com o **icpbrasil-truststore**!

## Pré-requisitos

- JDK 21 (Temurin recomendado)
- Não é necessário instalar Maven — use o wrapper (`./mvnw`)

## Build e testes

```bash
./mvnw verify
```

O CI também exercita fontes, Javadoc e metadados de release sem chave GPG ou
credenciais de publicação. Para reproduzir na raiz (requer Bash e Python 3):

```bash
./mvnw -B -ntp clean verify -Prelease -Dgpg.skip=true
bash scripts/verify-release.sh
```

O ZIP em `target/release-inspection/unsigned-bundle.zip` serve apenas para
inspeção local, não para upload. Não usar `deploy` ou o goal `publish` como
dry-run, nem com `skipPublishing=true`; veja a limitação em [MAINTAINERS.md](MAINTAINERS.md).

Os testes de integração (marcados com `@Tag("integration")`) dependem de rede externa
(repositório do ITI) e **não** rodam no build padrão. Para executá-los:

```bash
./mvnw verify -Pintegration-tests
```

O relatório de cobertura JaCoCo é gerado por módulo em `<módulo>/target/site/jacoco/index.html`.

## Dependências

O Dependabot abre PR semanal para atualizações do Maven e das GitHub Actions.
Para checar manualmente se algo ficou desatualizado fora desse ciclo:

```bash
./mvnw versions:display-dependency-updates
```

## Padrão de commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/pt-br/) com mensagens
em **português**, em uma linha. Exemplos:

```
feat: adiciona verificação de revogação via CRL
fix: corrige parse de bundle PKCS#7 com encoding PEM
docs: atualiza instruções de configuração do S3
```

## Fluxo de Pull Request

1. Crie uma branch a partir de `main`.
2. Faça as alterações com commits no padrão acima.
3. Garanta que o build de release sem assinatura e a inspeção local acima estão verdes.
4. Abra o PR contra `main` e aguarde o CI (GitHub Actions) passar.

## Vulnerabilidades de segurança

Não abra issues públicas para vulnerabilidades. Siga as instruções do
[SECURITY.md](SECURITY.md) para reporte responsável.

## Mantenedores

O processo de release, a gestão da chave GPG (renovação e revogação) e os secrets
do environment `release` estão documentados em um local único: [MAINTAINERS.md](MAINTAINERS.md).
