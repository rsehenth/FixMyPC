# FIX MY PC — Etapa 10: auditoria para lançamento público

Data: 21/11/2026 · Executor: Claude Opus 5.5 · Escopo: código atual do workspace, sem coleta real do Windows.

## 1. Resumo executivo

A base está sólida: o gate AST, o consentimento, a escrita confinada (`CreateNew`, recusa de UNC/ADS/dispositivo/reparse point) e a sanitização resistiram à revisão. Não encontrei P0. Encontrei e corrigi **1 P1** (cartão de nota afirmava "nenhum problema" com um achado presente, reproduzido no laudo real da Etapa 9) e **6 P2** localizados (outros 3 P2 ficaram abertos por dependerem de decisão), entre eles um defeito de distribuição que fazia `-ValidateOnly` falhar no pacote público e a saída padrão gravada dentro da pasta instalada. Também implementei o botão **Imprimir / Salvar em PDF** com CSP por hash (ver `OPUS-5.5-STAGE10-PRINT-PDF.md`).

Continuam abertos, por exigirem decisão do proprietário ou mudança arquitetural: licença e revisão jurídica, verificação de ACL da pasta de saída, timeout para `Get-WinEvent`/`Get-ScheduledTask`, assinatura de código/procedência e a homologação em VM. Por isso o parecer é **NO-GO para publicação** e **GO WITH CONDITIONS para homologação controlada** (ver `PUBLIC-RELEASE-READINESS.md`).

Validação final offline (21/11/2026): Run.Tests **447/447**, Collector.Tests **85/85**, Visual.Tests **307/307**, `-ValidateOnly` PASS, `Test-DistributionManifest` PASS, pacote em cópia limpa PASS. Todas as suítes usam fixtures/mocks; os testes de CLI rodam contra um projeto-espelho cujos coletores lançam exceção.

Ressalva de independência: auditei e modifiquei o mesmo código. Uma revisão independente final continua necessária.

## 2. Arquitetura (inventário)

| Camada | Arquivos | Observação |
|---|---|---|
| Entrada | `fixmypc.ps1` | Scanner AST → locales → consentimento → validação de caminhos → coletores (só no ramo real) → regras → nota → sanitização → HTML/JSON |
| Política | `src/security/ReadOnlyPolicy.ps1` | Allowlist de comandos/parâmetros, membros .NET, setters por tipo, caminhos e consultas em listas fechadas |
| Coleta | `src/collectors/*.ps1` (6) | CIM com `-OperationTimeoutSec 15`; `Get-WinEvent` limitado por nível, janela e `MaxEvents` (2000/log) |
| Análise | `src/analysis/*.ps1`, `rules/rules.json` | 22 regras determinísticas, pesos 30/25/20/15/10, `scoreAlgorithmVersion` 2.0 |
| Privacidade | `src/security/Privacy.ps1` | Regras por campo + regex global + limites de tamanho |
| Relatório | `src/reports/HtmlRenderer.ps1`, `templates/style.css` | HTML só a partir do documento sanitizado; CSP restritiva |
| Distribuição | `distribution-manifest.json`, `tools/Test-DistributionManifest.ps1` | Grupos runtime/development/neverShip; bloqueios `LICENSE-PENDING`, `LEGAL-REVIEW` |

## 3. Superfícies de ataque consideradas

1. Código-fonte adulterado → barrado pelo scanner antes de carregar módulos (exit 2). Não protege contra quem já pode editar o scanner.
2. Argumentos de linha de comando (`-OutDir`, `-Fixture`) → caminho qualificado local obrigatório; UNC, `\\?\`, ADS (`:`), nomes reservados, componentes terminados em ponto/espaço e reparse points são recusados; `CreateNew` impede sobrescrita.
3. Dados do sistema exibidos no HTML (nomes de serviços, provedores, programas) → `HtmlEncode` em todo dado; teste XSS (V3) com `<script>`, `onerror`, `javascript:`, `<iframe>`, `<style>`.
4. Arquivo HTML aberto no navegador → CSP `default-src 'none'`, sem rede, um único script autorizado por hash.
5. Agente de IA que monte a linha de comando → `-AcceptReadOnlyPolicy` é declaração, não prova (FMP-09); documentado em `SKILL.md`/adaptadores.
6. Compartilhamento do JSON/HTML → sanitização sem promessa de anonimização (ver §5).

## 4. Segurança somente leitura e consentimento

- **Comandos e provedores.** Allowlist fechada (`Get-CimInstance`, `Get-WinEvent`, `Get-Process`, `Get-Volume`, `Get-PhysicalDisk`, `Get-ScheduledTask`, `Get-ItemProperty`, `Get-Item`, `Get-ChildItem`, `Get-MpComputerStatus`, `Get-HotFix`, `Start-Sleep`) com parâmetros listados; classes CIM, namespaces, logs, chaves de filtro e caminhos de registro em listas fechadas. Lista de comandos proibidos como defesa em profundidade. `Win32_Product`, APIs de rede, `reg/sc/schtasks/wmic/...` e elevação são detectados no texto.
- **Execução dinâmica.** `& $var`, splatting, membros dinâmicos, `Invoke-Expression`, `Import-Module` e construtores fora da lista são recusados.
- **Mudança nesta etapa.** Exceção nova e restrita ao papel `writer`: `[System.Security.Cryptography.SHA256]::Create().ComputeHash(...)` e `[Convert]::ToBase64String`, para o hash CSP do script de impressão. Cálculo em memória, sem E/S.
- **Garantias e limites** agora documentados em `docs/readonly-policy.md` ("Garantias e limites do scanner"): o scanner é barreira estática conservadora, não sandbox; não cobre efeitos internos de provedores (CIM/WMI, Event Log, Task Scheduler, autoload de módulos do sistema) nem a integridade do PowerShell/.NET.
- **Consentimento.** Verificado no código e nos testes existentes (suite I): `-Yes` sozinho → exit 3 antes de carregar coletores; host não interativo sem flag → exit 3; fixture inválida/vazia não cai na coleta real; consentimento negado não cria pasta. `-ValidateOnly` sai antes do consentimento. A interrupção (Ctrl+C) durante a coleta não deixa artefatos porque toda escrita ocorre no fim (análise estática; não exercitado com coleta real nesta etapa).

## 5. Privacidade

Camadas distinguidas:

1. **Dados internos** (`diagnostic-internal.json`, só com `-IncludeInternalJson`): sem redação, ficam no computador.
2. **Dados sanitizados** (`diagnostic-sanitized.json`): contas, IDs de dispositivo, caminhos, mensagens, linhas de comando, seriais, rótulos de volume e assinantes substituídos; SIDs, LUIDs, GUIDs, IPv4/IPv6, MAC, e-mails e credenciais mascarados por regex; nome do computador, usuário e domínio mascarados.
3. **HTML**: renderizado exclusivamente do documento sanitizado (o renderizador lança exceção caso contrário).
4. **Compartilhável externamente**: decisão do usuário após revisão. Nomes de produtos, processos, serviços, provedores e modelos de disco permanecem e podem identificar software/hardware instalado.

Problemas encontrados por cenários sintéticos (todos corrigidos, testes R7):

- Chaves de dicionário não passavam pelos identificadores privados (latente: os coletores atuais não usam chaves derivadas de dados).
- IPv6 não era mascarado (defesa em profundidade: coletores não coletam endereços).
- `USERDOMAIN`/`USERDNSDOMAIN` não entravam na lista de identificadores.

**Exportação para IA.** O CLI e o laudo incentivavam anexar o JSON "à sua conversa com uma IA". O texto agora diz em PT-BR e EN que compartilhar é opcional, que o arquivo deve ser revisado, que pode conter metadados sensíveis, que nada é enviado automaticamente e que a anonimização não é perfeita. Não existe envio automático no produto.

## 6. Precisão diagnóstica

- **Regras e pontuação.** Revisei ativação, estados desconhecidos e deduplicação nas 22 regras. Estados `unknown`, `access_denied`, `unsupported`, `not_collected` e `error` nunca reduzem a nota; categorias sem evidência ficam fora e a nota é renormalizada; risco crítico limita a 49. Não alterei pesos, limiares nem o algoritmo.
- **5.1 Contradição.** Confirmada no laudo real: "93/100 · risco elevado · 1 achado" ao lado de "Nenhum problema encontrado nas verificações concluídas". Corrigido (S10-01).
- **5.2 Localização.** Confirmados "1 achados", "em 18,9." sem unidade e tempos de módulo sem "ms". Corrigido (S10-04).
- **5.3 SMART.** O laudo já dizia que SMART indisponível não confirma saúde, mas exibia "Saúde: Healthy" sem origem. Agora o rótulo é "Saúde (informada pelo Windows)" e a nota de SMART diz que o estado do provedor não certifica integridade física. `access_denied`/`unknown` continuam inconclusivos (S10-05).
- **5.4 Eventos.** O selo "OK" do log passou a "Consulta concluída"/"Query completed" (S10-11).
- **5.5 Volsnap #36.** A regra `storage.disk_event_errors` não afirmava defeito físico, mas agrupava Volsnap com erros de disco. O texto agora diz que os eventos não comprovam defeito físico e que Volsnap costuma refletir limite de espaço de cópias de sombra. Peso e severidade inalterados (6 pontos, `review_recommended`) — remover Volsnap da regra seria mudança metodológica, deixada para decisão (S10-12).
- **5.6 `os.w10_eol=unknown` no Windows 11.** Comportamento correto: o retrato de ciclo de vida cobre só Home/Pro; Enterprise/Education têm ciclos de 36 meses e não são inferidos. `unknown` não penaliza, mas reduz a cobertura do SO (1/2). Recomendo: (a) renomear a regra em versão futura (cobre Windows 10 e 11), (b) decidir se Enterprise/Education entram no retrato, (c) conferir a data de Windows 11 25H2 Home/Pro (`2027-10-13` no retrato; a segunda terça-feira de outubro de 2027 é 12/10) contra a página oficial antes do lançamento (S10-16).

## 7. Confiabilidade e desempenho

- CIM: todas as consultas têm `-OperationTimeoutSec 15`.
- `Get-WinEvent`: sem timeout nativo; limitado por `Level 1,2`, janela de 7 dias e `MaxEvents` 2000/log, o que limita memória. `Get-ScheduledTask`: sem timeout. Um provedor travado bloqueia a execução até Ctrl+C. Uma solução segura exige runspace com espera limitada e abandono (sem matar processos do Windows) — mudança arquitetural não implementada (S10-08).
- Falhas isoladas viram estados `error`/`access_denied` por módulo; conclusão parcial é refletida em cobertura e confiança.
- Execução real da Etapa 9: ~19 s, pico observado 255,6 MiB. Não executei testes de carga no host.

## 8. Acessibilidade e HTML

Revisão do laudo real e das amostras: hierarquia e identidade v2 preservadas; sem redesign. Botão novo nativo (`<button>`), foco visível, alvo de 40 px, alto contraste (`forced-colors`) e oculto na impressão. Testado em Chromium (Playwright) a 320/375/768/1024/1440 px sem overflow horizontal; 320 px equivale a 400% de zoom em 1280 px. Não testados nesta etapa: leitor de tela, Edge (canal específico), impressão física. Valores brutos do provedor (`Healthy`, `Running`, `Ready`) seguem em inglês no PT-BR (S10-17).

## 9. Distribuição

- **Pacote em cópia limpa** (40 arquivos do grupo `runtime` copiados para fora do workspace): sem relatórios, logs, caches, `graphify-out/`, `tests/` ou `samples/`. `-ValidateOnly` **falhava** (exigia `tests\Run.Tests.ps1`); corrigido (S10-03). Após a correção: `-ValidateOnly`, `-Help` e execução de fixture passaram na cópia limpa.
- `.gitignore` cobre saída real, logs, caches de agentes, segredos e pacotes. O manifesto mantém `LICENSE-PENDING` e `LEGAL-REVIEW`.
- Não há assinatura Authenticode nem arquivo de checksums; `SKILL.md` declara `license: MIT` no frontmatter, em conflito com `LICENSE-PENDING` (não alterado: decisão do proprietário).
- Dependências: nenhuma externa; só Windows PowerShell 5.1, .NET Framework e módulos do Windows (Storage, ScheduledTasks, Defender). Assets v2 próprios do projeto, titularidade ainda sem registro formal.

## 10. Achados

Formato: ID · severidade · arquivo/função · evidência · impacto · reprodução segura · correção · teste · situação.

| ID | Sev. | Arquivo / função | Evidência e impacto | Reprodução segura | Correção | Teste | Situação |
|---|---|---|---|---|---|---|---|
| S10-01 | P1 | `HtmlRenderer.ps1` / `Get-FmpSummaryBodyHtml` | Nota provisória sempre usava `report.score.provisionalNote` ("Nenhum problema encontrado") mesmo com achados. Mensagem diagnóstica falsa no cartão principal. | Fixture `limited-access.json` + grupo Volsnap #36 recente | Chave `report.score.provisionalNote.findings` quando há achados-base | Run R1 | **Corrigido** |
| S10-02 | P2 | `fixmypc.ps1` (saída padrão); READMEs | Saída padrão em `<instalação>\out\`; exemplos usavam `C:\temp\...`, que herda leitura para Usuários Autenticados. Laudos legíveis por outras contas. | Leitura do código; ACL padrão de `C:\` | Padrão `%LOCALAPPDATA%\FixMyPC\fixmypc-<data>-<id>`; sem `%LOCALAPPDATA%` → exit 3; aviso antes do consentimento fora do perfil; exemplos corrigidos | Run R8 | **Corrigido** (verificação de ACL: S10-09) |
| S10-03 | P2 | `ReadOnlyPolicy.ps1` / `Test-FmpReadOnlyCompliance` | `-ValidateOnly` exigia `tests\Run.Tests.ps1`, ausente do pacote; comando documentado falhava (exit 2) para o usuário final. | Cópia limpa do grupo runtime | Teste só escaneado se existir; fontes de produção seguem obrigatórias | Run R9 + cópia limpa | **Corrigido** |
| S10-04 | P2 | `HtmlRenderer.ps1` (resumo, metodologia), locales | "1 achados", "em 18,9." sem unidade, durações sem "ms". | Laudo real Etapa 9 | `Get-FmpCountText` (.one/.other), "segundos/seconds", coluna "Duração" em ms | Run R2 | **Corrigido** |
| S10-05 | P2 | locales (`table.health`, `report.storage.smart.none`) | "Saúde: Healthy" sem origem ao lado de SMART negado. | Laudo real | Rótulo "informada pelo Windows" e nota de não certificação | Run R3 | **Corrigido** |
| S10-06 | P2 | locales (`cli.review.steps`, notas de privacidade e passos de revisão do laudo), READMEs, `SKILL.md` | Incentivo a anexar JSON a IA sem ressalvas. | Laudo real | Texto opcional/revisado/sem envio/sem anonimização perfeita | Run R6 | **Corrigido** |
| S10-07 | P2 | `README.md`, `README.pt-BR.md` | Alegava compatibilidade com PowerShell 7 sem homologação. | Leitura | Declara apenas Win11 + PS 5.1 validados | — | **Corrigido** |
| S10-08 | P2 | `Events.ps1`, `Startup.ps1` | `Get-WinEvent`/`Get-ScheduledTask` sem timeout; provedor travado bloqueia a execução. | Não reproduzido (exigiria provedor travado) | Runspace com espera limitada e abandono, sem matar processos | — | **Aberto** (decisão arquitetural) |
| S10-09 | P2 | `fixmypc.ps1` | A ferramenta não verifica ACL da pasta escolhida; só avisa fora do perfil. | — | Ler ACL (somente leitura) exige incluir `Get-Acl` na allowlist: mudança de política | — | **Aberto** (decisão de política) |
| S10-10 | P2 | distribuição | Sem assinatura Authenticode, sem `SHA256SUMS`, sem `SECURITY.md`/`PRIVACY.md` com canal de contato. | — | Ver plano de fechamento | — | **Aberto** (decisão do proprietário) |
| S10-11 | P3 | `Get-FmpEventsSectionHtml` | Selo "OK" do log parecia "sem problemas". | Laudo real | "Consulta concluída" | Run R4 | **Corrigido** |
| S10-12 | P3 | locales (`rules.storage.disk_event_errors.detail`) | Volsnap agrupado como "erros de armazenamento". | Laudo real | Texto sem afirmar defeito físico; peso inalterado | Run R5 | **Corrigido** |
| S10-13 | P3 | `Privacy.ps1` | Chaves não sanitizadas com identificadores; IPv6; domínio. | Sondas sintéticas | Ver §5 | Run R7 | **Corrigido** |
| S10-14 | P3 | `fixmypc.ps1` | Retorno de `Assert-FmpOutputPath` impresso: listava `diagnostic-internal.json` sem `-IncludeInternalJson`. | Execução de fixture | `$null =` | Run R8 | **Corrigido** |
| S10-15 | P3 | `Write-FmpUtf8File` (sequencial) | Falha de E/S entre artefatos pode deixar conjunto parcial. | — | Gravar em nomes temporários e renomear ao final | — | **Aberto** (melhoria) |
| S10-16 | P3 | `Rules.ps1` / `rules.json` | `os.w10_eol` cobre Win11 apesar do nome; Enterprise fora do retrato; data 25H2 a conferir. | Leitura | Ver §6 | — | **Aberto** |
| S10-17 | P3 | renderer | Valores do provedor (`Healthy`, `Running`) não traduzidos. | Laudo real | Mapa de valores conhecidos | — | **Aberto** |
| S10-18 | P3 | `Run.Tests.ps1` | Deixa `out\fmp-tests-*` após a execução (P3-04 anterior). | Execução | Limpeza no fim da suíte | — | **Aberto** |
| S10-19 | P3 | CLI | "Pontuação: 79/100 (Pontuação)" redundante. | Execução de fixture | Omitir rótulo quando status `ok` | — | **Aberto** |

## 11. Correções implementadas (arquivos)

`fixmypc.ps1`, `src/reports/HtmlRenderer.ps1`, `src/security/Privacy.ps1`, `src/security/ReadOnlyPolicy.ps1`, `templates/style.css`, `locales/pt-BR.json`, `locales/en.json` (16 chaves novas, 7 alteradas, paridade 438/438), `tests/Run.Tests.ps1` (suite R, 24 verificações; 3 asserções de "zero script" adaptadas), `tests/Visual.Tests.ps1` (suite V13; asserções de CSP/script adaptadas ao contrato novo), `README.md`, `README.pt-BR.md`, `SKILL.md`, `CHANGELOG.md`, `docs/readonly-policy.md`, `docs/visual-integration.md`, `samples/` (regeneradas a partir de fixtures), `docs/screenshots/stage10-*.png`.

Compatibilidade: schema JSON inalterado (`1.0.0`), nenhum campo novo; algoritmo de nota inalterado (2.0). Laudos antigos continuam válidos; só o texto do HTML mudou.

## 12. Pendências históricas

- Homologação em VM (Windows 10/11, PS 5.1/7, usuário comum/administrador, política corporativa) — `docs/homologation-plan.md`.
- Modo Completo nunca executado em máquina real.
- `LICENSE-PENDING`, `LEGAL-REVIEW` e titularidade da arte v2.
- Exceção do Impeccable com wildcard (`.impeccable/config.json`, apontada pelo GPT-SOL): arquivo de ferramenta local, `neverShip`; sem efeito no pacote.
