# FIX MY PC — Etapa 11: verificação independente pré-lançamento

Data: 21/11/2026 · Verificador: agente independente (briefing "GPT Terra 6.1"; executado por Claude Opus 5.5 em sessão nova, sem herdar o contexto da Etapa 10) · Objeto: release candidato v0.1.0 no workspace atual.

Restrições cumpridas: nenhuma coleta real, nenhuma elevação, nenhuma ACL alterada, nenhum código de produção alterado, nenhum commit/push/publicação, nenhuma dependência global instalada. Tudo foi executado com fixtures sintéticas e cópias em pasta temporária da sessão. As ACLs do host foram apenas **lidas** (`Get-Acl`).

> Ressalva de independência: o briefing atribui esta etapa ao "GPT Terra 6.1". Ela foi executada por outro modelo da mesma família do executor da Etapa 10, mas em sessão nova e verificando o código, não os pareceres. O proprietário deve decidir se isso satisfaz o item A8.

## Veredito

**GO COM RESSALVAS PARA HOMOLOGAÇÃO.**
**NO-GO para publicação pública.**

A base técnica confere com o que a Etapa 10 relatou: suítes, CSP, pacote e consentimento resistiram à verificação independente. Mas encontrei um **bloqueador de privacidade reproduzido** (S11-01): a ferramenta não garante que os relatórios fiquem privados, nem no destino padrão, e o aviso atual dá falsa segurança dentro do perfil. A correção é pequena e deve entrar **antes** da homologação, para que a VM valide o comportamento final.

Ressalvas para a homologação: (1) aplicar S11-01/S11-02 antes, ou o operador cria manualmente um `-OutDir` novo com ACL protegida — **cumprida: S11-01 a S11-04 foram corrigidos a pedido do proprietário (§11)**; (2) cada execução real exige autorização específica do proprietário (o consentimento da Etapa 9 não vale); (3) VM descartável com snapshot.

## 1. O que foi verificado independentemente

| Área | Como | Resultado |
|---|---|---|
| Diretório de saída e ACL | Leitura do código (`fixmypc.ps1` 148–194, `Common.ps1` 256–324); `Get-Acl` do host; execuções de fixture em pastas com ACL permissiva herdada | **Bloqueador** S11-01, S11-02 |
| Consentimento | Pacote isolado: `-Yes` sem `-AcceptReadOnlyPolicy` | exit 3, pasta não criada ✔ |
| Escrita confinada | Pacote isolado: UNC, pasta com artefatos existentes, fixture inexistente | exit 3 nos três ✔ |
| Scanner AST | Cópia do pacote com `Remove-Item` injetado em `System.ps1` | `-ValidateOnly` exit 2 ✔ |
| Botão Imprimir / CSP | Inspeção estática + Chromium (Playwright, `file://`, offline) com 5 adulterações e 1 fixture de injeção | Sem falhas ✔ |
| Precisão diagnóstica | Locales, `Rules.ps1`, `rules.json`, laudo de fixture renderizado | Correções conferem; 1 P3 de data |
| Confiabilidade | `Events.ps1`, `Startup.ps1`, ordem de escrita em `fixmypc.ps1` | S10-08 confirmado; não bloqueia beta se documentado |
| Pacote | Reconstrução a partir do manifesto, 2 vezes, hash por arquivo, varredura de conteúdo | 40 arquivos, reprodutível ✔ |
| Licença | `LICENSE`, `NOTICE.md`, `SKILL.md`, manifesto, origem de ícones/fontes/assets | Inconsistência confirmada (decisão do proprietário) |
| Divulgação ao usuário | Textos de consentimento, `SKILL.md`, READMEs, adaptadores | Lacuna S11-03 |

## 2. Achados

### Confirmados (novos)

| ID | Sev. | Onde | Evidência | Impacto |
|---|---|---|---|---|
| **S11-01** | **P1 — bloqueador** | `Common.ps1` `New-FmpOutputDirectory` (l. 297–302); comentário `fixmypc.ps1` l. 151–152 | `CreateDirectory` sem `DirectorySecurity`: a pasta e os arquivos herdam a ACL do pai. **Neste host**, `%LOCALAPPDATA%` tem ACE herdável `CodexSandboxUsers: ReadAndExecute (ContainerInherit, ObjectInherit)`. A pasta `FixMyPC` só está privada porque foi criada à mão com ACL protegida na Etapa 9. Sem ela, o destino padrão herdaria leitura para outra conta. Reproduzido com fixture: saída em pasta sob o perfil com `Todos: FullControl` herdado → `report.html` e JSON com `Todos: FullControl`, **sem nenhum aviso** (exit 0). | A garantia "relatório privado" depende do estado da máquina. O comentário "standard Windows ACL is private" é falso em perfis com ACEs extras (sandbox, gestão corporativa, ferramentas de terceiros). Pasta `-OutDir` preexistente com ACL aberta é aceita. |
| **S11-02** | P2 | `fixmypc.ps1` l. 160–166 | O aviso só dispara fora de `%USERPROFILE%`. Pastas sob o perfil com ACL aberta e **pastas sincronizadas** (`%USERPROFILE%\OneDrive\...`) não geram aviso. Reproduzido: saída em `OneDrive\x` → exit 0, aviso ausente. | Relatório pode ir para a nuvem sem o usuário perceber. |
| **S11-03** | P2 — bloqueador de publicação (só texto) | `SKILL.md` passo 5, adaptadores, READMEs, `cli.policy.points` | O produto é distribuído como *skill* para agentes de IA. O `SKILL.md` manda o agente **ler `diagnostic-sanitized.json`** e a saída do console (que inclui o caminho com o nome do usuário). Esse conteúdo é processado pelo provedor de IA. Nenhum documento informa isso. O consentimento diz "No data is sent to the internet", o que é verdade só para o script. | Expectativa de privacidade incorreta no modo de uso principal. |
| S11-04 | P3 | `fixmypc.ps1` l. 7 e 45 | `-Help` ainda diz `default: out\<timestamp>`. O exemplo do cabeçalho usa `-OutDir C:\temp\auditoria`. Neste host `C:\temp` concede `Usuários autenticados: Modify`. A Etapa 10 disse que os exemplos foram corrigidos (S10-02): só os READMEs foram. | Orienta o usuário para uma pasta compartilhada. |
| S11-05 | P3 | `rules.json` l. 32 | Windows 11 25H2 Home/Pro: `2027-10-13`. A segunda terça-feira de outubro de 2027 é **12/10/2027** (calculado). Confirma S10-16. 24H2 Home/Pro (13/10/2026) já venceu: a regra passa a marcar esses PCs, comportamento correto. | Erro de 1 dia; exige conferência na página oficial e manutenção do retrato. |
| S11-06 | P3 | `docs/reviews/SONNET-5.5-STAGE9-REAL-SIMPLE-VALIDATION.md` | Contém nome de usuário, nome do host e grupo local do computador do proprietário. Fora do pacote runtime, mas iria a público se o código-fonte for aberto. | Exposição pessoal em repositório público. |

### Confirmados da Etapa 10 (reverificados)

S10-01 (nota com achados), S10-03 (`-ValidateOnly` no pacote), S10-04 (plural/unidades), S10-05 (rótulo de saúde), S10-11 (consulta concluída), S10-12 (Volsnap) e S10-14 conferem no código e no laudo de fixture renderizado. S10-18 confirmado: `Run.Tests` deixou `out\fmp-tests-27a2…` após esta execução. S10-19 também aparece no cartão HTML ("79 /100 · Pontuação").

### Descartados ou rebaixados

- **S10-09 (verificação de ACL por `Get-Acl`)**: substituído por S11-01. Não é preciso ler ACL: basta **criar** a pasta nova já com DACL protegida. Isso não altera nenhum objeto existente do host.
- **Risco de `style-src 'unsafe-inline'`**: só seria explorável com injeção de HTML, que não ocorre (todo dado é codificado; teste de injeção abaixo).
- **"print() fora do handler"**: o único `print` fora do `addEventListener` é o id `fmp-print`. Falso positivo da minha varredura.

## 3. Testes executados e códigos de saída

| Execução | Exit | Resultado |
|---|---|---|
| `tests\Run.Tests.ps1` | 0 | 447 passaram, 0 falharam (231 s) |
| `tests\Collector.Tests.ps1` | 0 | 85/85; todos os cmdlets de coleta mockados |
| `tests\Visual.Tests.ps1` | 0 | 307/307 |
| `tools\Test-DistributionManifest.ps1` | 0 | PASS ("NOT release approval") |
| `fixmypc.ps1 -ValidateOnly` (workspace) | 0 | PASS |
| Pacote isolado: `-ValidateOnly` / `-Help` | 0 / 0 | PASS |
| Pacote isolado: fixture `limited-access.json` | 0 | `report.html` + JSON sanitizado |
| Pacote isolado: `-Yes` sem consentimento | 3 | Nenhuma pasta criada |
| Pacote isolado: fixture inexistente / pasta com artefatos / UNC | 3 / 3 / 3 | Recusado |
| Pacote adulterado (`Remove-Item` em coletor) `-ValidateOnly` | 2 | Bloqueado pelo scanner |
| Fixture com saída sob o perfil e ACL `Todos` herdada | 0 | **Gravou sem aviso** (S11-01) |
| Fixture com saída em `D:\…\out\` (fora do perfil) | 0 | Aviso exibido |
| Fixture com saída em `OneDrive\x` | 0 | **Sem aviso** (S11-02) |

Isolamento das suítes: `Collector.Tests` define mocks para `Get-WinEvent`, `Get-CimInstance`, `Get-ScheduledTask`, `Get-PhysicalDisk`, `Get-Volume`, `Get-Process`, `Get-MpComputerStatus`, `Get-HotFix`, `Get-ItemProperty` e `Get-ChildItem`. `Run.Tests` só chama o CLI com `-AcceptReadOnlyPolicy` contra um espelho cujos coletores fazem `throw 'SYNTHETIC_COLLECTOR_REACHED'`.

Incidente desta etapa: a sonda de OneDrive gravou um laudo **sintético** (fixture, sem dados do host) em `C:\Users\<usuário>\OneDrive\x`. Removi a pasta segundos depois, mas o OneDrive pode tê-la sincronizado e mantido na lixeira online. Vale conferir e esvaziar. A pasta de sonda em `out\` também foi removida.

## 4. Botão Imprimir / PDF

Nenhuma falha encontrada.

| Verificação | Resultado |
|---|---|
| Um único `<script>`, estático, no fim do `body` | ✔ (`document.scripts.length` = 1, inclusive no laudo com injeção) |
| Hash CSP | Recalculado de forma independente: `KJzMA/LPo3dojY5+SKhGJu13nzTwvWXnwmdoyoBK0g4=`, igual ao da CSP |
| `script-src` sem `unsafe-inline`/`unsafe-eval`; `default-src 'none'`, `base-uri 'none'`, `form-action 'none'` | ✔ |
| Handlers inline / `javascript:` / `http(s)` no laudo limpo | 0 / 0 / 0 |
| Impressão automática | 0 chamadas no carregamento (PT-BR, EN, injeção, 5 adulterações) |
| Teclado | Tab: link de pulo → botão; Enter = 1 chamada, Espaço = +1; contorno de foco 2 px sólido |
| Nome acessível | "Imprimir / Salvar em PDF" / "Print / Save as PDF" |
| Ausente na impressão | `.print-action { display: none }` em `media=print` |
| Fallback | Dica "Você também pode usar Ctrl+P." / "You can also press Ctrl+P."; botão nasce `hidden` |
| A4 | `@page { size: a4; margin: 14mm 13mm 18mm }` com numeração; PDF headless gerado (PT-BR 582 KB, EN 577 KB) |
| Visual | Desktop 1280 px e impressão A4 conferidos por captura; 375 px sem overflow horizontal |

Casos sintéticos de adulteração (Chromium, `window.print` instrumentado):

| Caso | Efeito |
|---|---|
| T1: byte alterado no script autorizado | Script bloqueado pela CSP; botão permanece oculto |
| T2: `<script>` inline extra | Bloqueado (1 violação CSP); título inalterado |
| T3: `<img onerror>` + link `javascript:` clicado | Ambos bloqueados (2 violações); título inalterado |
| T4: `<script src>` e `<img src>` externos | Bloqueados com `net::ERR_BLOCKED_BY_CSP`; nenhuma resposta de rede |
| T5: `eval()` no lugar do script | Hash não confere → bloqueado; botão oculto |
| Fixture com `<script>`, `onerror`, `<button id="fmp-print" onclick>`, `</style><script src>` em nomes de programas e discos | Tudo codificado como texto; um único `#fmp-print`; zero execução e zero rede |

Limitação já conhecida e correta: quem reescreve o arquivo HTML inteiro também reescreve a CSP.

## 5. Riscos de privacidade

1. **S11-01**: privacidade da pasta de saída depende da ACL herdada. Reproduzido neste host.
2. **S11-02**: pastas sincronizadas com nuvem dentro do perfil não geram aviso.
3. **S11-03**: no modo *skill*, o JSON sanitizado e a saída do console vão para o provedor de IA sem aviso.
4. Residuais já documentados e aceitáveis: o JSON sanitizado ainda identifica software e hardware; o `-IncludeInternalJson` não é redigido; Administradores locais sempre conseguem ler arquivos do perfil.

## 6. P2 ainda abertos

| ID | Situação | Posição desta verificação |
|---|---|---|
| S10-08 (timeout `Get-WinEvent`/`Get-ScheduledTask`) | Confirmado: sem limite. `Get-WinEvent` é limitado por nível, janela e `MaxEvents`; `Get-ScheduledTask` não. A escrita só ocorre no fim, então Ctrl+C não deixa artefatos. | **Aceitável para homologação e beta**, desde que documentado em Limitações (hoje os READMEs não mencionam travamento nem Ctrl+C). Medir a duração na homologação. Runspace com abandono fica para depois. |
| S10-09 (ACL) | Substituído por S11-01 | **Bloqueador** com correção mínima abaixo |
| S10-10 (procedência) | Sem `SHA256SUMS`, sem Authenticode, sem `SECURITY.md`/`PRIVACY.md` | `SHA256SUMS` obrigatório antes de publicar (processo na §9). Authenticode e `SECURITY.md` recomendados, não bloqueiam um beta. |
| S11-02, S11-03 | Novos | S11-03 bloqueia a publicação (correção só de texto) |

## 7. Bloqueadores de publicação

1. ~~**S11-01** — saída privada por construção (código).~~ Corrigido (§11).
2. ~~**S11-03** — divulgação do processamento por IA (texto).~~ Corrigido (§11).
3. **Licença** — `LICENSE-PENDING` (decisão do proprietário).
4. **LEGAL-REVIEW** — nome/marca e titularidade dos assets v2 (proprietário + jurídico).
5. **Homologação em VM** com resultados registrados (matriz §8).
6. **`SHA256SUMS`** publicado junto do ZIP.

Não bloqueiam: S10-08 documentado, S11-02 (entra junto com S11-01), S11-04 a S11-06, P3 da Etapa 10.

## 8. Matriz de homologação (Windows 11, VM limpa)

Pré-condições: snapshot antes de cada cenário; conta de teste sem dados reais; ProcMon filtrado por processo `powershell.exe` (escrita em arquivo, registro e rede); Wireshark ou firewall registrando saída; autorização do proprietário **por execução**; nenhum laudo enviado a serviços externos.

| # | Cenário | Configuração | Aceite |
|---|---|---|---|
| H1 | Modo Simples, usuário padrão, PS 5.1 | Padrão `%LOCALAPPDATA%` | exit 0; escrita só na pasta de saída; zero rede; pasta criada com DACL protegida (usuário + SYSTEM [+ Administradores]) |
| H2 | Modo Completo, usuário padrão | Idem | Idem; módulos sem permissão como `access_denied`, nota sem penalidade por isso |
| H3 | Modo Simples, administrador (sem elevar) | Idem | Igual a H1; nenhum prompt de UAC |
| H4 | ACL permissiva herdada | Antes: adicionar ACE herdável `Users:Read` em `%LOCALAPPDATA%` **da VM** | Pasta nova **não** herda a ACE (após S11-01). Antes da correção: documenta a falha |
| H5 | `-OutDir` preexistente | Pasta existente vazia, com e sem ACL aberta | Recusa com exit 3 (após S11-01) |
| H6 | `-OutDir` em OneDrive/pasta sincronizada | OneDrive configurado na VM | Aviso exibido antes do consentimento |
| H7 | Falha de criação de diretório | Pai sem permissão de escrita; disco cheio (VHD pequeno) | exit 3/4 claro; nenhum artefato parcial ou conjunto parcial registrado (S10-15) |
| H8 | Coletores com acesso negado | Usuário padrão (Security log), serviço EventLog parado, Task Scheduler restrito por GPO | Módulo `error`/`access_denied`; cobertura e confiança reduzidas; laudo coerente |
| H9 | Sem programas opcionais | Defender desativado por política, sem OEM tools | `unsupported`/`not_collected`, sem penalidade |
| H10 | Rede desativada | Adaptador desconectado | Mesmo resultado de H1 |
| H11 | Desempenho | 3 execuções por modo | Duração e pico de memória registrados; limite de referência < 2 min no Simples |
| H12 | Cancelamento | Ctrl+C em cada módulo e durante a escrita | Sem artefato antes da fase de escrita; registrar o estado na fase de escrita |
| H13 | Impressão/PDF | Edge e Chrome da VM; "Salvar como PDF" em A4; impressora virtual | Botão ausente no PDF; numeração; nada cortado |
| H14 | Política corporativa | `AllSigned`, AppLocker/WDAC em auditoria, Constrained Language Mode | Falha clara, sem efeitos colaterais |
| H15 | Edições | Home, Pro, Enterprise; 23H2, 24H2, 25H2 | Regra de ciclo de vida: Home/Pro conforme retrato; Enterprise `unknown` |
| H16 | Modo *skill* | Claude Code e Codex na VM | Agente pede consentimento, usa pasta nova e mostra o aviso de S11-03 |

Fora do escopo até ser anunciado: Windows 10, PowerShell 7 (o `SKILL.md` l. 51 menciona `pwsh`; alinhar com o README, que diz "não validado").

## 9. Licença e distribuição

**Inconsistência confirmada.** `SKILL.md` declara `license: MIT`. `LICENSE` contém o texto MIT completo, que está **no grupo runtime**, e o manifesto mantém `LICENSE-PENDING`. `NOTICE.md` diz que MIT não foi confirmado. Na prática, quem publicar o pacote como está publica um arquivo MIT, e isso equivale a conceder a licença. Nada foi alterado.

Alternativas (decisão do proprietário):

| Opção | O que exige | Observações |
|---|---|---|
| A. Pacote público, código-fonte privado | Licença de uso do pacote (EULA curta) no lugar de `LICENSE`; `SKILL.md` com `license: Proprietary`; repositório privado | Os `.ps1` são legíveis no pacote de qualquer forma: "fonte privada" só vale para testes, ferramentas e histórico |
| B. Código visível, licença proprietária | `LICENSE` "All rights reserved" ou *source-available*; repositório público sem `docs/reviews` com dados pessoais (S11-06) | Permite auditoria pública sem conceder redistribuição |
| C. Open source | Confirmar MIT (ou outra) e alinhar `LICENSE`, `NOTICE.md`, frontmatter do `SKILL.md` e READMEs; remover `LICENSE-PENDING` | O caminho mais simples, porque os textos já estão prontos. Exige decidir antes a marca (LEGAL-REVIEW) |

**Terceiros.** Nenhuma dependência externa: só Windows PowerShell 5.1, .NET Framework e módulos do Windows. Os ícones SVG são declarados como "authored inline" (`HtmlRenderer.ps1` l. 147). Não há `@font-face` nem fontes embutidas: o CSS usa variável de fonte do sistema. Os assets v2 vêm de `tools/Optimize-Assets.ps1`. A **origem e a titularidade da arte-fonte** (`assets/branding`, `assets/report`) não estão registradas, e isso continua sob LEGAL-REVIEW. Se a arte foi gerada por IA, registrar a ferramenta e os termos aplicáveis.

**Processo reproduzível de distribuição** (validado nesta etapa):

1. A partir de um checkout limpo da tag, copiar somente os padrões `runtime` do manifesto (script usado: enumera os arquivos, aplica `-like` em cada padrão e copia preservando caminhos).
2. Resultado esperado: **40 arquivos**. SHA-256 da lista de hashes por arquivo: `da8afda2271958fdef95a1b16265d89d02bfdae9017a5929df39db25abdbeb4d` antes das correções (duas construções independentes deram o mesmo valor) e `4d0dbf70e8f0101395b3a3e3bc8129171260c5a5f00802ecf4146484e8cf4173` depois delas (§11). O valor muda a cada alteração de arquivo runtime: recalcular na tag final.
3. Na cópia isolada: `-ValidateOnly` = 0, `-Help` = 0, uma fixture = 0, `-Yes` sem consentimento = 3.
4. Varredura: nenhum `report.html`, `diagnostic-*.json`, `.log`, `tests/`, `samples/`, `graphify-out/`, cache de agente, nome de usuário, host, e-mail, chave ou token (0 ocorrências).
5. Compactar e publicar junto `SHA256SUMS.txt` com o hash do ZIP **e** os hashes por arquivo. Os hashes por arquivo são reprodutíveis; o do ZIP muda com os carimbos de data. Instruir: `Get-FileHash .\fixmypc-0.1.0.zip -Algorithm SHA256`.
6. Não pedir `Set-ExecutionPolicy Bypass` global. Usar `-ExecutionPolicy Bypass` por processo ou `Unblock-File` depois de conferir o hash.

Documentação: o README só afirma o que foi validado (Win11 + PS 5.1, Modo Simples). Exceções: `SKILL.md` l. 51 (`pwsh`) e o README l. 88, que diz que a ferramenta "nunca lê nem altera permissões". Essa frase precisa mudar com S11-01.

## 10. Menor lista possível de correções finais

| # | Correção | Tamanho | Teste de aceite |
|---|---|---|---|
| 1 | **S11-01**: em `New-FmpOutputDirectory`, recusar pasta de saída já existente e criá-la com `[IO.Directory]::CreateDirectory(path, DirectorySecurity)`. DACL protegida (`SetAccessRuleProtection($true,$false)`) com usuário atual (`WindowsIdentity::GetCurrent().User`) e SYSTEM em FullControl (Administradores opcional). Liberar no scanner, só para o papel `writer`, os construtores `DirectorySecurity` e `FileSystemAccessRule` e essa sobrecarga. Corrigir o comentário l. 151–152. | ~15 linhas + allowlist | Teste: pai com ACE herdável `Users:Read` → pasta nova sem essa ACE; `-OutDir` existente → exit 3 |
| 2 | **S11-02**: aviso antes do consentimento quando a saída está sob `$env:OneDrive`, `$env:OneDriveCommercial` ou `$env:OneDriveConsumer`. Reescrever `cli.outdir.notPrivate`: a pasta é criada privada; pastas sincronizadas podem ir para a nuvem. | ~5 linhas + 2 chaves de locale | Fixture com `OneDrive` simulado → aviso |
| 3 | **S11-03**: uma frase em `SKILL.md` (passo 5), adaptadores e READMEs: "Ao usar via agente de IA, o agente lê o JSON sanitizado e a saída do console; esse conteúdo é processado pelo serviço de IA conforme os termos dele." Mesma ressalva no ponto "No data is sent to the internet". | Texto | Revisão |
| 4 | **S11-04**: `-Help` com o padrão real e exemplo do cabeçalho sem `C:\temp`. | 2 linhas | `-Help` |
| 5 | Documentar S10-08 em Limitações (travamento possível, Ctrl+C, nada gravado). | Texto | Revisão |
| 6 | Proprietário: licença (opção A/B/C), LEGAL-REVIEW, registro da origem da arte v2. Retirar `docs/reviews/SONNET-5.5-STAGE9…` de um repositório público. | Decisão | `Test-DistributionManifest` PASS sem bloqueios |
| 7 | Gerar ZIP + `SHA256SUMS.txt` pelo processo da §9. | Processo | Hash confere em máquina limpa |
| 8 | Homologação H1–H16 com autorização por execução. | VM | Matriz §8 registrada |

Opcional, não bloqueia: S11-05 (conferir a data 25H2 na página oficial), S10-18 (limpeza de `out\fmp-tests-*`), S10-19 ("Pontuação" redundante), S10-15 (conjunto parcial em falha de E/S).

## 11. Correções aplicadas após o parecer (itens 1–4)

Autorizadas pelo proprietário depois da entrega do parecer. Itens 5–8 seguem abertos. Nenhuma ACL existente do host foi alterada; os testes só criam pastas novas na área de testes e na pasta temporária da sessão.

| ID | Situação | Arquivos | Verificação |
|---|---|---|---|
| S11-01 | **Corrigido** | `src/common/Common.ps1` (`New-FmpOutputDirectory` cria pastas com DACL protegida: usuário atual + SYSTEM, sem herança); `fixmypc.ps1` (recusa pasta de saída existente antes e logo depois da análise, exit 3); `src/security/ReadOnlyPolicy.ps1` (exceção só para `Common.ps1`: `DirectorySecurity`, `FileSystemAccessRule`, `WindowsIdentity::GetCurrent`, `SecurityIdentifier`/`LocalSystemSid`, `SetAccessRuleProtection`, `AddAccessRule`; `SetAccessControl` continua proibido) | Fixture sob pai com `Todos: FullControl` herdado → pasta, pais criados e `report.html` só com usuário + SYSTEM, ACL protegida. Pasta existente (com artefatos ou vazia) → exit 3. Testes `S11-01` (4) em `Run.Tests` |
| S11-02 | **Corrigido** | `fixmypc.ps1`; locales (`cli.outdir.notPrivate` reescrita, `cli.outdir.synced` nova) | Aviso antes do consentimento para unidade não NTFS/ReFS e para pasta sob `%OneDrive%`/`%OneDriveCommercial%`/`%OneDriveConsumer%`. Teste `S11-02` com `OneDrive` simulado (variável só no processo filho) |
| S11-03 | **Corrigido** | `SKILL.md` (passo 2), `adapters/claude/README.md`, `adapters/codex/AGENTS.md`, `README.md`, `README.pt-BR.md`, `cli.policy.points` (PT-BR/EN) | O agente avisa antes da execução que o JSON sanitizado e a saída do console são processados pelo serviço de IA |
| S11-04 | **Corrigido** | `fixmypc.ps1` (`-Help` com o padrão real; exemplo do cabeçalho em `%LOCALAPPDATA%`) | Teste `S11-04`; `-Help` conferido |
| Extra | Corrigido | `SKILL.md` | Removida a sugestão de `pwsh` (o `CreateDirectory` com segurança só existe no .NET Framework; no PowerShell 7 a execução deve falhar fechada, sem gravar; não testado) |

Documentação alinhada: `docs/readonly-policy.md` (nova exceção do scanner e texto da pasta de saída), `CHANGELOG.md`. Locales com paridade 440/440.

Testes após as correções:

| Execução | Exit | Resultado |
|---|---|---|
| `tests\Run.Tests.ps1` | 0 | **453/453** (447 + 6 novos S11; a asserção R8 do aviso antigo foi substituída) |
| `tests\Collector.Tests.ps1` | 0 | 85/85 |
| `tests\Visual.Tests.ps1` | 0 | 307/307 |
| `tools\Test-DistributionManifest.ps1` | 0 | PASS |
| `fixmypc.ps1 -ValidateOnly` | 0 | PASS (15 arquivos, nenhuma violação) |
| Pacote reconstruído (40 arquivos): `-ValidateOnly` / fixture / `-Yes` sem consentimento | 0 / 0 / 3 | Sem dados pessoais |

Limites que continuam: Administradores locais leem qualquer arquivo; há uma pequena janela entre a verificação "pasta não existe" e a criação (só explorável por quem já escreve na pasta-mãe; no padrão, o nome é aleatório); `-IncludeInternalJson` grava na mesma pasta privada. Na homologação, H4–H6 passam a validar esse comportamento.
