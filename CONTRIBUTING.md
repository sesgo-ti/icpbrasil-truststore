# Contribuindo

Obrigado pelo interesse em contribuir com o **icpbrasil-truststore**!

## Pré-requisitos

- JDK 21 (Temurin recomendado)
- Não é necessário instalar Maven — use o wrapper (`./mvnw`)

## Build e testes

```bash
./mvnw verify
```

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
3. Garanta que `./mvnw verify` está verde localmente.
4. Abra o PR contra `main` e aguarde o CI (GitHub Actions) passar.

## Vulnerabilidades de segurança

Não abra issues públicas para vulnerabilidades. Siga as instruções do
[SECURITY.md](SECURITY.md) para reporte responsável.

## Nota para mantenedores: chave GPG de release

A chave GPG de assinatura de releases (`566A199A481E3355`) expira em 2028-08-30.
Antes dessa data, um mantenedor deve renovar a validade via
`gpg --edit-key 566A199A481E3355 → expire` e reenviar ao keyserver.
