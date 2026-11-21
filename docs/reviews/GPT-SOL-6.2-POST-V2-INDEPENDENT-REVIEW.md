# FIX MY PC — Etapa 8 · Revisão independente pós-v2

**Data** 20 de novembro de 2026  
**Veredito** **BLOQUEADO para homologação controlada**

## 1. Resultado da revisão

A homologação deve aguardar a correção de dois defeitos nos artefatos que ela precisa validar. Um identificador de sessão por usuário permaneceu no JSON sanitizado e no HTML. O JSON também omitiu um aplicativo e declarou `truncated=false`. Reproduzi os dois defeitos em uma execução sintética da CLI.

A identidade v2 passou na inspeção visual e técnica. As suítes offline passaram com a adaptação de três chamadas descrita na seção 8. O manifesto passou no workspace completo e falhou na cópia sem dois diretórios locais classificados como `neverShip`.

Foram usadas como referências a [auditoria final](CLAUDE-OPUS-5.5-FINAL-AUDIT.md), a [correção FMP-01/FMP-04](CLAUDE-OPUS-5.5-FMP01-FMP04-FIX.md), o [hardening da Etapa 6 executado pelo Sonnet 5.5](GPT-SOL-6.2-P2-HARDENING.md), a [Etapa 7](SONNET-5.5-STAGE7-RELEASE-PREP.md) e a [Etapa 7.1](SONNET-5.5-STAGE7.1-VISUAL-FINAL.md). Os resultados abaixo vieram da inspeção do código e dos testes desta etapa. O repositório estava sem commits, por isso a comparação histórica usou os relatórios, as expectativas das suítes e as amostras disponíveis.

## 2. Segurança, consentimento e confinamento

- **Privacidade confirmada · corrigir antes da homologação.** `startup.autoServices[].displayName` conserva o LUID em nomes como `Sync Host_1a2b3`. O coletor grava o nome de exibição e o laudo o renderiza. A seção 5 traz a reprodução. [Startup.ps1, 215–230](../../src/collectors/Startup.ps1#L215) · [HtmlRenderer.ps1, 939–944](../../src/reports/HtmlRenderer.ps1#L939)
- **Consentimento e fixture.** O gate roda antes de carregar os coletores ou escrever artefatos. A execução sem consentimento em modo não interativo e com `-Yes` foi recusada pela CLI com coletores sentinela. A presença explícita de `-Fixture` seleciona o ramo sintético, com erro para argumento vazio ou documento inválido. O ramo real é o único que carrega os coletores. `-ValidateOnly` retorna antes dos dois ramos. O consentimento da CLI é declaratório quando fornecido por argumento e depende do operador e da aprovação por execução no host. [CLI, 88–110 e 154–211](../../fixmypc.ps1#L154) · [Adaptador Codex](../../adapters/codex/AGENTS.md)
- **Caminhos e registro.** `Get-FmpSafeRegistryPath` devolveu apenas a forma canônica de entradas listadas, incluindo a entrada de inventário com `Uninstall\*` prescrita pela lista. Rejeitou hive fora da lista, provedor qualificado, UNC sintético e caminho de dispositivo. `Get-FmpLocalPath` rejeitou UNC, prefixo de dispositivo, nome DOS reservado, fluxo alternativo e travessia em entradas sintéticas. Os testes chamaram os validadores com strings, sem abrir as fontes descritas. [ReadOnlyPolicy.ps1, 235 e 766](../../src/security/ReadOnlyPolicy.ps1#L766) · [Common.ps1, 256–285](../../src/common/Common.ps1#L256)
- **Artefatos.** O escritor exige diretório pai igual à raiz autorizada, verifica componentes existentes contra reparse points, abre com `CreateNew` e aplica 8 MiB por arquivo. As suítes confirmaram preservação de conteúdo pré-existente. A verificação por caminho e a abertura são operações separadas, por isso o confinamento depende de um diretório local novo com ACL restrita. A publicação dos três artefatos possíveis também é sequencial, conforme P3-12. [Common.ps1, 288–325](../../src/common/Common.ps1#L288) · [CLI, 287–300](../../fixmypc.ps1#L287)

## 3. Integridade do scanner AST

As listas fechadas de comandos, parâmetros, classes CIM, namespaces, logs, chaves de filtros e registro continuam no caminho obrigatório. A suíte L cobriu chamadas dinâmicas, membros .NET, setters, argumentos e origens de caminhos, com controles permitidos e rejeitados. `ValidateOnly` aprovou os 15 arquivos do inventário de validação, que inclui apenas `Run.Tests.ps1` entre as suítes. [ReadOnlyPolicy.ps1, 775–988 e 1015](../../src/security/ReadOnlyPolicy.ps1#L775) · [Run.Tests.ps1, suíte L](../../tests/Run.Tests.ps1#L812)

**Lacuna confirmada na prova de receptores.** Um texto sintético contendo somente um dicionário local com a entrada `numbers` igual a `[int]7` e uma chamada `Clear` nesse membro obteve `Ok=True` em `Test-FmpScriptCompliance -Role collector`. O trecho foi analisado como texto e jamais executado. A exceção prova o tipo da raiz e deixa sem prova o membro nas operações aceitas. Os retornos de funções internas também recebem uma classificação manual por nome, sem inferência interprocedural. São limites relevantes ao revisar métodos .NET, wrappers internos e caminhos dinâmicos. A correção mínima é exigir prova do membro nas operações mutáveis ou manter exceções estreitas e auditadas, além de explicitar e testar os contratos dos produtores classificados. [ReadOnlyPolicy.ps1, 172–206 e 615–652](../../src/security/ReadOnlyPolicy.ps1#L172)

**Fronteira de confiança.** A CLI e o scanner executado como bootstrap pertencem à base confiável. Os papéis são derivados do caminho absoluto, e alguns tipos de chamada recebem exceções locais. A classificação por caminho pode variar com o diretório de instalação, conforme P3-15. O scanner estabelece conformidade estática para a versão inspecionada. A observação de efeitos de provedores, cmdlets e autoload pertence à futura homologação em VM. [CLI, 31–70](../../fixmypc.ps1#L31) · [ReadOnlyPolicy.ps1, 149–160 e 877–983](../../src/security/ReadOnlyPolicy.ps1#L149)

## 4. Confiabilidade diagnóstica

| Item | Resultado |
|---|---|
| **FMP-01** | A nota usa apenas pesos elegíveis e renormaliza o denominador. Categorias sem regra-base penalizável ou evidência ficam fora. Penalidades duplicadas usam o maior valor do grupo. O risco crítico confirmado mantém o teto configurado em 49, inclusive com boa cobertura. |
| **FMP-04** | Os dois catálogos carregaram 417 chaves. Os seis laudos frescos foram gerados sem aviso de chave ausente. As limitações conhecidas têm traduções verificadas pela suíte. Limitação nova sem tradução mantém o fallback canônico previsto. |
| **FMP-05** | No cenário com 3% livre, a condição crítica aparece antes de `<10%`. Os testes conservaram penalidades 10 e 6 e desconto deduplicado de 10. |
| **FMP-06** | 100 serviços automáticos, por si, não geraram alerta. Uma fixture com 40 itens acionáveis e 100 serviços reportou 40, sem desconto. Resta acoplamento na completude do check. Com um item, todas as fontes de itens acionáveis conclusivas e apenas `startup.autoServices` negado, a regra sintética devolveu `access_denied`. Isso empobrece o diagnóstico de Inicialização, fora da pontuação. Restringir a checagem de completude às fontes contadas. |
| **FMP-07** | Três amostras em cerca de 4 s geram uma observação informativa, sem penalidade. Média, máximo, quantidade e janela continuam disponíveis. Os dois idiomas descrevem a janela sem concluir carga persistente. |

Referências de implementação e regressão. [HealthScore.ps1, 30–243](../../src/analysis/HealthScore.ps1#L30) · [Rules.ps1, 493–527](../../src/analysis/Rules.ps1#L493) · [Run.Tests.ps1, suítes J/K/M/O](../../tests/Run.Tests.ps1#L553)

Seis execuções novas da CLI com fixtures, três estados em PT-BR e EN. Cada execução produziu JSON sanitizado e HTML, com `scoreAlgorithmVersion="2.0"` no JSON. Os números, estados e textos localizados foram conferidos no HTML.

| Fixture | Nota | Estado | Risco | Cobertura | Confiança |
|---|---:|---|---|---:|---|
| `critical-disk.json` | 49 | `ok` | `critical` | 100% (15/15) | alta |
| `limited-access.json` | 100 | `provisional` | `none_detected` | 86,7% (13/15) | média |
| `degenerate.json` | `null` | `unavailable` | `undetermined` | 0% (0/15) | baixa |

O `ok` da primeira linha indica disponibilidade da nota. O HTML exibe o risco crítico ao lado dela. O cartão provisório informa a cobertura parcial, e o indisponível usa travessão e omite o medidor. A versão permanece opcional no schema para aceitar documentos antigos. [HtmlRenderer.ps1, 450–511](../../src/reports/HtmlRenderer.ps1#L450) · [Schema, 278–288](../../schemas/diagnostic.schema.json#L278)

## 5. Privacidade e sanitização

**Regressão a acrescentar para FMP-08.** A reprodução usa somente o sanitizador e dados inventados. A saída observada foi `name="OneSyncSvc_<LUID>"` e `displayName="Sync Host_1a2b3"`. O Windows usa o mesmo sufixo no nome técnico e no nome de exibição. A regex atual exige que o prefixo termine em `Svc` ou `Service` e deixa escapar o nome de exibição de um serviço automático real previsto pelo coletor. Sanitizar os dois campos no contexto da mesma entrada e verificar o JSON e o HTML. [Privacy.ps1, 64–73](../../src/security/Privacy.ps1#L64) · [Serviços por usuário no Windows](https://learn.microsoft.com/en-us/windows/application-management/per-user-services-in-windows)

```powershell
. .\src\common\Common.ps1
. .\src\security\Privacy.ps1
$doc = [ordered]@{ startup = [ordered]@{ autoServices = @(
    [ordered]@{ name = 'OneSyncSvc_1a2b3'; displayName = 'Sync Host_1a2b3' }
) } }
(ConvertTo-FmpSanitizedDiagnostic $doc).startup.autoServices | ConvertTo-Json -Compress
```

SIDs locais e Azure AD nos formatos cobertos foram mascarados, com preservação de SIDs conhecidos. A contraprova sintética mostrou que nomes privados em chaves de objetos e nomes compostos como `FMPHOST.example.test` podem sobreviver. Um IPv6 documental também permaneceu. A chave não recebe a lista de identificadores, e a regex de valores exige limites que incluem o ponto. A origem desses três exemplos no fluxo real ficou sem confirmação. O sanitizado continua contendo inventário capaz de identificar software e requer revisão humana antes de compartilhamento. O JSON interno permanece opt-in. [Privacy.ps1, 75–143](../../src/security/Privacy.ps1#L75) · [CLI, 276–300](../../fixmypc.ps1#L276)

**Confirmação ponta a ponta.** Em uma cópia de `demo-synthetic.json`, substituí `startup.autoServices` pelo serviço sintético acima e `advanced.installedApps` por `status="ok"`, `totalCount=151`, `truncated=false` e 151 objetos com nomes de `Synthetic App 1` a `Synthetic App 151`. A CLI com `-Fixture -Mode full -Language pt-BR` exibiu `Sync Host_1a2b3` no JSON e no HTML. O JSON conservou o total 151 e `truncated=false` com 150 itens. O sanitizador isolado reproduziu o corte com `items=@(1..151)`. O coletor permite até 300. Acrescentar um indicador do corte de sanitização, preservando o indicador de limite da coleta. Validar 150 e 151 itens e refletir o corte no laudo quando aplicável. [Privacy.ps1, 103–141](../../src/security/Privacy.ps1#L103) · [Advanced.ps1, 247–281](../../src/collectors/Advanced.ps1#L247)

## 6. FMP-10 e identidade v2

**Resolvido no escopo visual e técnico.** Inspecionei lado a lado os nove originais e as nove versões otimizadas — banner, logo, ícone, visão geral, achados, hardware, armazenamento, inicialização e privacidade. As imagens usam figuras genéricas de diagnóstico, sem logotipos de terceiros ou selos de aprovação fixa. O banner e o logo conservam a palavra `Windows` na descrição do produto. A inspeção foi independente das flags do registro de revisão de marca.

Recalculei SHA-256, tamanho e dimensões dos nove pares e confirmei igualdade byte a byte entre a variante otimizada e seu Base64 decodificado. Nenhum dos 18 hashes das artes retiradas reapareceu. Cada um dos 12 HTML sob `samples/` referencia os nove hashes atuais, tem a CSP exata da Etapa 7, zero scripts, zero atributos de evento, zero imports CSS e zero recursos externos. O maior tem **774.857 bytes**, abaixo de 8 MiB. Screenshots de desenvolvimento registram versões anteriores e ficam fora do pacote de runtime. [Manifesto de assets](../../assets/optimized/manifest.json) · [CSS e CSP do renderizador](../../src/reports/HtmlRenderer.ps1#L1208) · [CSP anterior](SONNET-5.5-STAGE7-RELEASE-PREP.md#8-segurança-csp--xss)

## 7. Impeccable e escopo da exceção

Com o binário instalado **4.9.1**, `detect --json templates/style.css` e a mesma execução com `--no-config` emitiram os dois avisos nas linhas 131 e 139. O caminho absoluto com barras invertidas foi reconhecido em `ignores list` e não filtrou o detector CLI neste Windows. O comportamento do hook instalado ficou sem execução direta.

Na cópia de teste acrescentei uma terceira faixa sintética. A regra `side-tab=*` com escopo relativo `templates/style.css` suprimiu os três avisos, inclusive o adicional. A exceção oficial `impeccable-disable-line side-tab`, nas duas declarações aprovadas, deixou exatamente o terceiro aviso. `--no-inline-ignores` voltou a mostrar os três.

Recomendo retirar o wildcard e, caso se queira silenciar as duas ocorrências aprovadas, aplicar a exceção oficial por linha apenas às duas declarações, com o motivo da aprovação. O escopo por arquivo no JSON não distingue seletores ou ocorrências de `side-tab`. [Config local](../../.impeccable/config.json) · [Faixas aprovadas](../../templates/style.css#L131) · [Contrato do detector](https://github.com/pbakaus/impeccable/blob/main/docs/CLI-CONTRACT.md)

## 8. Resultados dos testes offline

Antes de executar, conferi os pontos de entrada. Run e Visual usam fixtures ou análise/renderização local. Collector executa os seis coletores em runspaces com autoload desativado, provedores removidos, cmdlets de coleta substituídos por mocks/sentinelas e descoberta de aplicações/scripts desabilitada. As sondas de isolamento chamaram apenas os nomes bloqueados nesse runspace. A cópia temporária usou os scripts do workspace. No Run, três chamadas à CLI espelho foram feitas sem a flag de consentimento, conforme a restrição desta revisão. Permaneceram os casos de fixture inválida, fixture vazia e modo inválido. A invariância desses três casos na presença da flag ficou sem execução.

| Check | Resultado observado |
|---|---|
| `tests/Run.Tests.ps1` | **385/385**, zero falhas no resumo final, com as três variantes descritas. Inclui dois checks agregados do exit das suítes abaixo. O processo que capturava o log ficou aberto após o resumo, e seu código de saída ficou sem confirmação independente. |
| `tests/Collector.Tests.ps1` | **85/85**, exit 0. |
| `tests/Visual.Tests.ps1` | **290/290**, exit 0. |
| `fixmypc.ps1 -ValidateOnly` | **PASS**, exit 0. 15 arquivos, zero violações, 417 chaves por idioma e `rules.json` carregado. |
| `tools/Test-DistributionManifest.ps1` no workspace completo | **PASS**, exit 0, 1.201.608 bytes de runtime e dois bloqueios de release registrados. A execução foi feita na raiz original para conferir a classificação integral, em modo somente leitura. |
| Mesmo manifesto na cópia sem caches locais | **FAIL (2)**, exit 1. `.playwright-mcp/*` e `.commandcode/*` não correspondiam a arquivos. O checker exige presença de padrões de exclusão que deveriam ser opcionais. |
| PowerShell 7.6.9, verificação adicional | `ValidateOnly` e fixture crítica EN passaram. O JSON da fixture deu 49/100, risco crítico e algoritmo 2.0. As suítes completas da tabela rodaram no Windows PowerShell 5.1. |

As contagens são por suíte. O Windows PowerShell recusou a primeira invocação pelo AuthorizationManager. A execução bem-sucedida usou `-ExecutionPolicy RemoteSigned` no processo filho, como no harness do projeto.

### Navegador e cartão sticky

Chromium em modo offline abriu os seis exemplos críticos, provisórios e indisponíveis em PT-BR/EN, em 320 e 1440 px. Observei zero tentativas HTTP(S), imagens carregadas e zero overflow horizontal do documento. Também conferi os seis HTML recém-gerados. Em 1440 px, o cartão se manteve a 16 px do topo durante a rolagem dentro do resumo e saiu com o fim do painel. O efeito começa a 901 px, é estático a 900 e 320 px e fica estático no modo de impressão emulado. No exemplo crítico, o cartão ainda estava fixo 180 px após a posição inicial. Nos outros dois estados o painel acabava antes desse ponto. [Regra responsiva](../../templates/style.css#L257)

## 9. Classificação dos 15 P3 originais

| ID | Classificação | Estado e correção mínima |
|---|---|---|
| P3-01 | Versão posterior | O formatador percorre valores e substitui tokens em cascata. Usar substituição em uma passagem. O escape HTML continua posterior à formatação. |
| P3-02 | Versão posterior | `Math.Round` aplica arredondamento para o par em empates. Registrar a política atual e só alterá-la junto com o contrato da nota. |
| P3-03 | Antes da publicação | `.gitignore` e manifesto existem. Tornar opcionais os padrões `neverShip` ausentes e exercitar o pacote com lista de inclusão em raiz limpa. Mover a saída padrão para diretório privado fora da skill. Para homologação, exigir `OutDir` absoluto, novo e com ACL restrita. |
| P3-04 | Versão posterior | As suítes usam `out/` e Run deixa temporários. A cópia isolada evita poluir o projeto. Migrar para temporários gerenciados ou documentar a limpeza. |
| P3-05 | Versão posterior | O relato atual identifica os dois agregados. Manter resultados por suíte e explicitar a semântica no resumo se ele for usado em automação. |
| P3-06 | Antes da publicação | Fixtures com `advanced.signatures.status="ok"` exercitam um cenário que o coletor real sempre marca `not_collected`. Identificá-las como testes de regra e alinhar as fixtures que representam execuções reais. |
| P3-07 | Antes da homologação | Corte do JSON confirmado com 151 itens, mantendo `truncated=false`. Sinalizar perda no estágio de sanitização. |
| P3-08 | Antes da publicação | Reliability Records cortam em 100 antes de qualquer ordenação garantida. Ordenar por data decrescente antes do corte e indicar amostra limitada. |
| P3-09 | Antes da publicação | Release Health e Lifecycle em en-GB indicam 12/10/2027 para 25H2 Home/Pro. Lifecycle em en-US exibe 13/10/2027 e a variante detalhada termina às 06:59:59. A diferença é compatível com a apresentação em fusos distintos. Fixar a convenção de fuso/dia antes de mudar a data. Em teste sintético, 26H1 e 26H2 já resultam em `unknown` por ausência da tabela. Atualizar o snapshot e testar a fronteira. [Release Health](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information) · [Lifecycle en-GB](https://learn.microsoft.com/en-gb/lifecycle/products/windows-11-home-and-pro) · [Lifecycle en-US](https://learn.microsoft.com/en-US/lifecycle/products/windows-11-home-and-pro?source=recommendations) |
| P3-10 | Antes da publicação | Um hotfix sintético de 335 dias devolveu `pass` com o limiar de 365. Explicitar que nenhum hotfix CBS acima do limiar foi detectado. Preservar o limiar até existir política aprovada. |
| P3-11 | Antes da publicação | Falhas auxiliares de memória/CPU e da associação volume–disco podem ficar sem um motivo explícito. Registrar limitação localizada quando a consulta auxiliar falhar. |
| P3-12 | Antes da publicação | Falha de I/O posterior à primeira escrita pode deixar saída parcial, mesmo após pré-validar tamanhos. Identificar conjunto incompleto ou publicar o conjunto após concluir as escritas. Na homologação, tratar exit diferente de zero como execução inválida. |
| P3-13 | Versão posterior | Atualizar o cabeçalho do harness para descrever isolamento de cmdlets e helpers com mocks. A matriz em VM deve medir o comportamento real de APIs .NET e provedores. |
| P3-14 | Versão posterior · código já corrigido | Rodapé A4 localizado e media query `forced-colors` presentes. Restam validações com impressão e configuração de acessibilidade reais. |
| P3-15 | Antes da publicação · parcial | Banner v2 neutro confirmado. Fixture só com dispositivos 22/45 ainda gerou achado `attention` de penalidade zero. Separar dispositivos desativados/desconectados de defeitos. Classificar arquivos da AST pelo caminho relativo à raiz, com teste de instalações aninhadas. [Código 22](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/cm-prob-disabled) · [Código 45](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/cm-prob-phantom) |

## 10. Pendências para homologação controlada

1. Fechar a exposição do LUID e o truncamento silencioso. Cobrir ambos com fixtures e regressões nos artefatos de saída.
2. Após a aprovação específica do operador, usar VM Windows dedicada e snapshotada, identidade de teste e saída nova com ACL restrita. Validar Windows 10/11 e PowerShell 5.1/7, com monitoramento externo de rede, escrita e duração. Confrontar o inventário e os estados do laudo com as condições conhecidas da VM. [Plano de homologação](../homologation-plan.md)
3. Revisar os primeiros artefatos localmente antes de compartilhar. Registrar a integridade do conjunto e o exit da CLI a cada cenário.

## 11. Pendências para publicação

Revalidar o manifesto numa cópia limpa após corrigir os padrões opcionais e conferir o conteúdo efetivo do pacote. Resolver os itens classificados para publicação, a dependência do `OutDir` padrão e a exceção do Impeccable com escopo por ocorrência. Registrar a aceitação dos limites da AST ou endurecer as exceções de tipos nos pontos identificados. O manifesto conserva os bloqueios `LICENSE-PENDING` e `LEGAL-REVIEW`. A titularidade e o uso da arte v2 também exigem decisão do proprietário. [Manifesto de distribuição](../../distribution-manifest.json)

## 12. Plano mínimo de correções

1. Em `Privacy.ps1`, tratar os dois nomes de instâncias por usuário no contexto de `autoServices` e marcar coleções cortadas. Acrescentar fixtures com nome técnico, nome de exibição, nome comum preservado e limites de 150/151.
2. No checker de distribuição, permitir ausência de padrões `neverShip` e conservar exclusividade dos grupos e bloqueio de artefatos proibidos em runtime. Repetir com e sem caches locais.
3. Ajustar a abrangência de `startup.high_count` à completude das fontes acionáveis e restringir as exceções verificadas do scanner e do detector. Repetir as suítes offline e validar os três estados em ambos os idiomas.

## 13. Riscos residuais e limites da evidência

Provedores, autoload, comportamento real com privilégios variados, ACL herdada, concorrência fora do processo, links durante a janela de abertura, diferenças entre edições Windows e outros navegadores continuam pendentes de validação. A leitura em PowerShell 7 foi parcial. Também ficaram pendentes leitor de tela, impressão física e alto contraste nativo.

`ValidateOnly` levou cerca de 8,2 s em 5.1 e 6,0 s em 7.6.9 nesta execução. A medida inclui inicialização do PowerShell e validação de regras e idiomas. O valor coincide com a referência de 5.1 da Etapa 6, sem base comparável para atribuir regressão atual ao scanner. Medir separadamente na homologação.

## 14. Veredito

**BLOQUEADO para homologação controlada.** O JSON e o HTML são parte do objeto da homologação. O vazamento confirmado de LUID e o truncamento silencioso comprometem essa etapa até que ambos sejam corrigidos e retestados. Esta revisão executou somente a trilha offline e registrou evidências no presente parecer. A autorização para homologar ou publicar depende de decisão separada do proprietário.
