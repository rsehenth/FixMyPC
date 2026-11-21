# FIX MY PC — Etapa 11.1: auditoria Git, `.gitignore`, licença e READMEs

Data: 21/11/2026 · Executor: Claude Sonnet 5.5 · Escopo: arquivos Git e documentação. Não é autorização para lançar o software.

## Classificação: **PRONTO COM RESSALVAS**

Os arquivos estão prontos para a **revisão de publicação**. Nada foi commitado, enviado ou publicado. Ressalvas: o relatório da Etapa 9 foi mantido só local (decisão sua pendente), 27 capturas de tela antigas mostram o logotipo do Windows e não devem ser publicadas, e a revisão jurídica e a titularidade da arte seguem abertas (seção 13).

## 1. Estado atual do Git

| Item | Resultado |
|---|---|
| Branch | `main`, **sem nenhum commit** |
| Arquivos rastreados (`git ls-files`) | 0 |
| Staged (`git diff --cached`) | 0 |
| Modificados | 0 (nada é rastreado) |
| Não rastreados e não ignorados | 173 (98 de texto, 75 imagens) |
| Ignorados | 317 caminhos, todos em pastas locais de ferramentas (ver seção 3) + o relatório da Etapa 9 |

Como o repositório não tem commits nem índice, **não há exposição no histórico** (seção 8). O risco está em um futuro `git add .`, que é o que o `.gitignore` e esta auditoria tratam.

## 2. Arquivos rastreados

Nenhum. Os 173 candidatos à primeira inclusão estão classificados na seção 14.

## 3. Arquivos ignorados

| Origem | Conteúdo | Observação |
|---|---|---|
| `.playwright-mcp/` | 19 logs de console e 2 `.yml` de páginas | Capturas locais de navegador. Um log, segundo a auditoria Opus, pertence a outra aplicação |
| `graphify-out/` | cache, grafo e relatório do graphify | Estado de ferramenta; o grafo traz nomes de arquivos e rótulos internos |
| `.commandcode/`, `.impeccable/` | `taste.md`, configuração e cache de hook | Estado local de agentes |
| `out/` | vazia | Pasta de saída histórica |
| `docs/reviews/SONNET-5.5-STAGE9-REAL-SIMPLE-VALIDATION.md` | relatório da homologação real | **Ignorado nesta etapa de propósito** (seção 6) |

Nenhum arquivo foi apagado do disco.

## 4. Regras adicionadas ao `.gitignore`

- Caminhos: `auditoria-*/`, `fmp-tests-*/`.
- Relatório local da Etapa 9: `/docs/reviews/SONNET-5.5-STAGE9-REAL-SIMPLE-VALIDATION.md`.
- Ferramentas: `.playwright-cli/`, `.codebase-memory/`.
- IDE e editores: `.vscode/`, `.idea/`, `.vs/`, `*.code-workspace`, `*.suo`, `*.user`, `*.swo`, `*~`, `*.rej`.
- Python e Node: `__pycache__/`, `*.py[cod]`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.venv/`, `venv/`, `env/`, `node_modules/`, `npm-debug.log*`, `.npm/`.
- Backups e pacotes: `*.backup`, `build/`, `*.tar`, `*.tar.gz`, `*.tgz`.
- Segredos: exceção `!.env.example`, para que o modelo de configuração possa ser versionado.

## 5. Regras removidas ou corrigidas

- Removida a regra `console-*.log` (redundante com `*.log`).
- Corrigida a regra `.env.*`, que impedia versionar `.env.example`.
- Nenhum padrão genérico foi criado: `*.json`, `*.html`, `*.ps1`, `*.png` e `assets/` continuam rastreáveis. `**/report.html` e `**/diagnostic-*.json` seguem exatos; as amostras sintéticas usam outros nomes (`demo-report.html`, `demo-diagnostic-*.json`).

**Verificação regra a regra (`git check-ignore -v`).** 28 caminhos representativos que devem ser ignorados: todos casaram com a regra esperada. 25 caminhos que precisam continuar versionáveis (`fixmypc.ps1`, `SKILL.md`, `LICENSE`, manifesto, schemas, locales, templates, assets oficiais, fixtures, samples, adaptadores, ferramentas, `.gitignore`, `.env.example`): nenhum ignorado. `git check-ignore -q .env.example` retorna 1 (não ignorado); o `-v` mostra a linha da exceção, que não significa ignorar.

**Escopos diferentes.** O `.gitignore` decide o que o Git vê; o manifesto decide o ZIP runtime. Os grupos `development` (`tests/`, `tools/`, `samples/`, `docs/reviews/*`, `docs/screenshots/*`, assets-fonte) podem ir ao repositório, mas ficam fora do ZIP. O ignorar do relatório da Etapa 9 não afeta o manifesto (`Test-DistributionManifest` passa).

## 6. Arquivos sensíveis encontrados (sem reproduzir valores)

Varredura de todos os arquivos candidatos por nome de usuário, nome do computador, domínio, e-mail, conta Git, caminhos `C:\Users\`, SIDs, GUIDs, IPv4, MAC, chaves e tokens.

| Arquivo | Categoria | Situação |
|---|---|---|
| `docs/reviews/SONNET-5.5-STAGE9-REAL-SIMPLE-VALIDATION.md` | **Nome real da conta Windows** em dois caminhos de perfil; versão exata do build do Windows e do PowerShell; nome de grupo local de sandbox; nome da pasta de execução; dados reais da máquina (nota, cobertura, evento) | **Ignorado**. Ver recomendação abaixo |
| `docs/reviews/*.md` (7 arquivos) | Caminho local do workspace de desenvolvimento (uma ocorrência por arquivo) | Baixo risco; não identifica pessoa. Aceitável ou limpar na revisão final |
| `tests/Run.Tests.ps1`, `tests/Collector.Tests.ps1`, `tests/fixtures/*.json`, `docs/reviews/CLAUDE-OPUS-5.5-FINAL-AUDIT.md`, `docs/reviews/opus-5.5-evidence/*` | Nomes de usuário, SIDs, e-mail, IP, senha e token **fictícios**, usados como entrada dos testes do sanitizador | Sintéticos e intencionais. Podem ser versionados. Falsos positivos de varredura automática de segredos são esperados |
| Demais texto | Nenhuma ocorrência de nome de usuário, nome do computador, domínio ou conta Git; nenhuma chave ou token real |

Capturas (75 PNG): 5 foram abertas e verificadas. Todas mostram **relatórios de demonstração sintéticos**, com aviso "dados sintéticos" e sem dados pessoais. As demais não foram inspecionadas uma a uma; os nomes e as datas indicam o mesmo conteúdo sintético, mas a conferência final é sua.

**Recomendação sobre a Etapa 9** (nada foi removido nem alterado no disco): (a) manter só local, como está; ou (b) publicar uma versão sanitizada, com `%USERPROFILE%` no lugar do perfil, sem build exato, sem nome de grupo e sem a pasta de execução. O mérito do documento (primeira validação real) já aparece nos READMEs de forma genérica.

**Atualização:** você escolheu a opção (b). Foi criada `SONNET-5.5-STAGE9-REAL-SIMPLE-VALIDATION-PUBLIC.md` (não ignorada, pronta para versionar), com o caminho de perfil trocado por `%LOCALAPPDATA%`, build e versão exatos do Windows/PowerShell omitidos, nome do grupo de sandbox generalizado, pasta de execução e identificador do evento removidos. Mantidos: resultados da validação (nota, cobertura, módulos, tempos). O original continua só local e ignorado. Varredura da cópia: 0 ocorrências de usuário, computador, `C:\Users`, caminho do workspace ou build.

## 7. Arquivos já rastreados que exigem atenção

Nenhum, porque nada está rastreado. Se algum dia um arquivo sensível for rastreado, o `.gitignore` não o protege: a remoção do índice (`git rm --cached`) e, se já houver commit, a reescrita do histórico exigiriam sua autorização específica. Nenhum desses comandos foi usado.

## 8. Possível exposição no histórico

Nenhuma: `git rev-list --all` retorna 0 commits, não há tags nem stash e o índice está vazio. Ao fazer o primeiro commit, a identidade configurada no Git (nome e e-mail do autor) ficará pública junto com ele; confirme que é a desejada.

## 9. Situação das capturas de tela

| Grupo | Arquivos | Situação |
|---|---|---|
| Arte antiga com **logotipo do Windows** e escudo de aprovação | 21 capturas de 20/11 às 13h (`desktop-*`, `tablet-*`, `mobile-*`, `lang-*`, `print-a4-*`, `state-*`) e 6 `stage7-*` | **Não publicar.** Conferido visualmente em 2 deles; os demais, por data e nome. Conflitam com a identidade v2 e com a política de marcas |
| `stage71-before-*` (5) | antes/depois da Etapa 7.1 | Documentam a correção; não usar na vitrine |
| v2 sintéticas conferidas | `stage71-final-critical-en-1440.png`, `stage10-print-btn-en-768.png`, `stage10-print-btn-ptBR-1440.png` | **Usadas nos READMEs** |
| Demais `stage71-*` e `stage10-*` | 22 arquivos | v2 sintéticas por data/nome; aguardam conferência visual |

Os arquivos antigos continuam não ignorados (são evidência de desenvolvimento). A decisão de excluí-los do repositório público é sua.

## 10. Estado dos READMEs

- `README.md` (inglês, principal) e `README.pt-BR.md` reescritos, com links entre eles no topo.
- Status visível no topo: **Still in Development — Functional Preview** / **Em desenvolvimento — Versão funcional de prévia**, gratuito para uso não comercial, sem selos de estabilidade ou certificação.
- Seções pedidas: visão geral, status, recursos, funcionamento, capacidades, relatórios, privacidade e segurança, requisitos, primeiros passos, modos, limitações, desenvolvimento e validação, capturas, licença, aviso legal.
- Paridade EN/PT: 19 seções, 5 blocos de código, 5 tabelas, 2 imagens, 55 itens de lista, 27 links, em ambos. Os blocos de código diferem apenas em idioma, comentários e nome da pasta de exemplo.

## 11. Problemas de documentação corrigidos

- README antigo dizia que a licença MIT era rascunho: substituído (seção 13).
- Divulgação do processamento por provedor de IA no modo skill, em destaque (privacidade e skill).
- Frase de requisito de uma única execução em hardware real separada de "testes sintéticos".
- Resultados de testes apresentados como sintéticos, não como homologação.
- `LICENSE (MIT)` em `IMPLEMENTATION-REPORT.md`; `PUBLIC-RELEASE-READINESS.md` (item 13) e `PUBLIC-RELEASE-REMEDIATION-PLAN.md` (A1) atualizados. Relatórios históricos de etapas anteriores que citam MIT ou `LICENSE-PENDING` foram **mantidos**, pois registram o que era verdade na época.
- Os documentos em `docs/` estão em português; isso é dito no README inglês.

## 12. Links e comandos verificados

- Links relativos e caminhos citados em `README.md`, `README.pt-BR.md` e `NOTICE.md`: 0 quebrados; âncoras internas conferidas. Único endereço externo nos READMEs: `https://agentskills.io` (já existia); `NOTICE.md` e `LICENSE` citam a URL canônica da PolyForm.
- `fixmypc.ps1 -Help`: exit 0, parâmetros conferem com o README (padrões: modo `simple`, idioma `pt-BR`).
- `fixmypc.ps1 -ValidateOnly`: PASS (15 arquivos, 0 violações; 440 chaves por locale).
- `tools/Test-DistributionManifest.ps1`: PASS; blocos de bloqueio registrados: `LEGAL-REVIEW`.
- `tests/Visual.Tests.ps1`: 307/307. `tests/Run.Tests.ps1`: 453/453 (inclui a suíte isolada dos coletores). Reexecutei porque o manifesto e uma asserção do V12 mudaram e o Run.Tests lê o texto dos READMEs; nenhuma coleta real do Windows foi feita.
- Grupo `runtime` do manifesto: 40 arquivos, como antes.
- Varredura de identificadores nos arquivos candidatos: 0 ocorrências de usuário, computador, domínio, e-mail ou conta Git; nenhum token real.
- Verificação de espaços em branco e marcadores de conflito nos arquivos editados: limpa. `git diff --check` não tem base de comparação sem commits.

Limite: os exemplos do README foram conferidos contra os parâmetros e o `-Help`; as execuções com `-AcceptReadOnlyPolicy` não foram rodadas aqui, porque seriam uma coleta real, fora do escopo.

## 13. Pendências jurídicas e de licença

**Decisão aplicada:** PolyForm Noncommercial License 1.0.0.

- `LICENSE`: texto oficial integral, baixado da tag `1.0.0` do repositório `polyformproject/polyform-licenses`, sem nenhuma alteração (hash idêntico ao arquivo baixado).
- `SKILL.md`: `license: PolyForm-Noncommercial-1.0.0` (identificador SPDX).
- `README.md`, `README.pt-BR.md`, `NOTICE.md`, `IMPLEMENTATION-REPORT.md`, `CHANGELOG.md`: alinhados. Descrita como *source-available*, gratuita para uso não comercial, sem a expressão "código aberto aprovado pela OSI" como afirmação positiva (aparece só negada, para deixar claro que não é). Se preferir que a expressão não apareça nem negada, é uma troca de uma frase.
- Manifesto: `LICENSE-PENDING` removido, com `LICENSE-CHOICE` registrado em `resolved`. Consistência comprovada nos cinco arquivos. `LEGAL-REVIEW` **mantido** e ampliado.
- `tests/Visual.Tests.ps1` (V12, linha 497): a asserção exigia `LICENSE-PENDING` no manifesto; passou a exigir que ele **não** conste e que `LEGAL-REVIEW` continue. Foi a única alteração em testes.

**Terceiros.** Verificado no código: nenhum `Import-Module`/`Install-Module`/`Add-Type`, nenhuma fonte ou `@import`, nenhuma biblioteca incluída; os ícones do relatório são desenhados no próprio renderizador. O uso do Windows PowerShell, do .NET Framework e dos recursos do Windows não envolve redistribuição. Não encontrei incompatibilidade de licença de terceiros.

**Marca e imagens.** `NOTICE.md` agora declara que a licença cobre o software e **não** estabelece titularidade do nome, do logotipo nem da arte v2 (`assets/branding`, `assets/report` e derivados `assets/optimized`, também embutidos nos laudos). Autor, ferramenta de criação (por exemplo, se foi gerada por IA) e termos **não estão registrados no repositório**.

**Dúvidas para sua decisão:**

1. **Titular dos direitos autorais.** O texto MIT antigo dizia "FIX MY PC contributors". A PolyForm usa linhas `Required Notice: Copyright ...`; não inventei uma. Precisa do seu nome ou da entidade.
2. **Arte dentro do pacote.** O pacote runtime inclui as imagens embutidas (`assets/optimized/embed/*.b64`). Quem receber o pacote pode entender que elas estão sob a PolyForm. Decida se a arte entra sob a mesma licença (e então precisa da sua titularidade) ou sob termos separados.
3. **Alcance de "não comercial".** A licença proíbe uso comercial, inclusive por uma empresa ou por técnico que cobre pelo serviço; só permite uso pessoal, por organizações sem fins lucrativos, educacionais e públicas (conforme o texto). Isso corresponde a "gratuito para uso não comercial", mas é mais restrito do que parece para quem usa o PC corporativo. Confirmar com advogado.
4. **Não é OSI.** Plataformas e a listagem de skills que exijam licença aprovada pela OSI podem recusar o projeto.
5. **Nome com "Windows" e marca FIX MY PC:** revisão jurídica continua pendente (`LEGAL-REVIEW`).
6. **Contribuições de terceiros.** Se aceitar contribuições, defina política (CLA ou equivalente); a PolyForm não resolve isso.

Bloqueios que permanecem para publicação pública, além dos de licença: `LEGAL-REVIEW`, homologação em VM, `SHA256SUMS`.

## 14. O que deve ou não ir para um repositório público

**Deve ir (seguro por esta auditoria):**
`fixmypc.ps1`, `SKILL.md`, `README.md`, `README.pt-BR.md`, `NOTICE.md`, `LICENSE`, `CHANGELOG.md`, `distribution-manifest.json`, `.gitignore`, `src/`, `rules/`, `locales/`, `templates/`, `schemas/`, `adapters/`, `docs/readonly-policy.md`, `docs/methodology.md`, `docs/visual-integration.md`, `docs/homologation-plan.md`, `tests/` (fixtures sintéticas), `tools/`, `samples/` (demonstrações sintéticas), `assets/optimized/manifest.json` e `assets/optimized/embed/*.b64` (**dependem de decidir a titularidade da arte, seção 13**), `docs/screenshots/stage71-final-*`, `stage10-*` (após conferência visual).

**Decisão sua antes de ir:** `assets/branding/`, `assets/report/`, `assets/optimized/branding|report/`, `assets/brand-review.json` (titularidade); `docs/reviews/*` (relatórios internos de IA; úteis como transparência, mas contêm caminho local do workspace e nomes de modelos); `IMPLEMENTATION-REPORT.md`.

**Não deve ir:**
`docs/reviews/SONNET-5.5-STAGE9-REAL-SIMPLE-VALIDATION.md` (original, ignorado; a cópia `-PUBLIC.md` pode ir), as 27 capturas com arte antiga (`desktop-*`, `tablet-*`, `mobile-*`, `lang-*`, `print-a4-*`, `state-*`, `stage7-*`) e as 5 `stage71-before-*`, `.playwright-mcp/`, `graphify-out/`, `.commandcode/`, `.impeccable/`, `out/`, qualquer `report.html` ou `diagnostic-*.json` reais, logs, `.env`, credenciais, ZIPs e backups.

**Fora do ZIP runtime, mas no repositório:** `tests/`, `tools/`, `samples/`, `docs/reviews/`, `docs/screenshots/`, `docs/homologation-plan.md`, `IMPLEMENTATION-REPORT.md`, assets-fonte e `distribution-manifest.json`. Os READMEs do ZIP apontam para capturas e relatórios que só existem no repositório; os links funcionam no GitHub e não funcionam dentro do ZIP.

## Alterações desta etapa

`.gitignore`, `LICENSE`, `SKILL.md`, `NOTICE.md`, `README.md`, `README.pt-BR.md`, `distribution-manifest.json`, `CHANGELOG.md`, `IMPLEMENTATION-REPORT.md` (uma linha), `tests/Visual.Tests.ps1` (uma asserção), `docs/reviews/PUBLIC-RELEASE-READINESS.md` (uma linha), `docs/reviews/PUBLIC-RELEASE-REMEDIATION-PLAN.md` (uma linha) e este relatório. Nenhum código de coletor, scanner AST, regra, locale ou HTML foi alterado.

Não foi feito: commit, push, criação de repositório ou release, `git rm --cached`, reset, clean, reescrita de histórico, apagamento de arquivos, coleta real do Windows.
