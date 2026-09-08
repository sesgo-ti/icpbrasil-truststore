# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/)
e o projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

> A versão 0.0.1 ainda **não foi lançada**. A data abaixo registra o fechamento
> da candidata local, não uma publicação no Maven Central ou uma tag existente.

## [Unreleased]

## 0.0.1 - 2026-09-08 (candidata, não publicada)

### Adicionado

- Arquitetura hexagonal em três módulos: `core` (Java puro, sem Spring/AWS), `autoconfigure` (wiring Spring Boot) e `rest` (microserviço standalone com fat jar).

- Download do acervo de ACs vigentes da ICP-Brasil (bundle ZIP oficial do ITI) com verificação de integridade por hash SHA-512.
- Cache em memória indexado por SKI (Subject Key Identifier), com TTL configurável e limiares de criticidade.
- Sincronização automática do acervo em background.
- Montagem de cadeia de certificados via AIA CA Issuers (suporte a DER, PEM e PKCS#7).
- Verificação de revogação via OCSP e CRL, com cache e fallback automático.
- Dois backends de armazenamento: filesystem local e S3-compatível (AWS S3, MinIO etc.).
- Auto-configuração Spring Boot, endpoint REST opcional de consulta por SKI e health indicator.
- `SSLContext` e `X509TrustManager` dedicados com trust exclusivo nas ACs da ICP-Brasil.
- Proteção contra SSRF e limites de tamanho para downloads derivados de extensões de certificados (AIA, OCSP, CRL).
- Evidências OCSP/CRL vinculadas ao certificado, cobertura e janela temporal; cache revalidado nas consultas.
- Snapshot atômico do acervo com validade limitada e readiness coerente com as consultas.
- Integrações AWS/Actuator opcionais e configuração filesystem mínima.
- Preparação de parent, core e autoconfigure para o Central, com fontes, Javadoc e verificação sem credenciais; REST fora da publicação.

[Unreleased]: https://github.com/sesgo-ti/icpbrasil-truststore/commits/main
