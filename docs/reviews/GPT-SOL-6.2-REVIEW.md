# FIX MY PC — Revisão técnica e hardening

**Etapa 2 · 20 de novembro de 2026 · v0.1.0**

## Resumo executivo

A revisão cobriu o ponto de entrada, a política somente leitura, todos os coletores, a análise, os artefatos e os adaptadores. O workspace continha 47 arquivos no início. O código declara seis coletores e 22 regras, com 15 regras-base comuns aos dois modos e sete exclusivas da Completa.

A auditoria real ficou fora do escopo. Toda execução usou análise estática, fixtures locais ou cópias do CLI com coletores fictícios que interrompem a execução ao serem carregados. Nenhum processo de teste leu os logs, os processos, os serviços, o registro, os drivers, o SMART ou o inventário do computador anfitrião. A fase não publicou nem instalou software.

## Arquivos analisados

| Superfície | Arquivos |
|---|---|
| Entrada, segurança e I/O | [fixmypc.ps1](../../fixmypc.ps1), [ReadOnlyPolicy.ps1](../../src/security/ReadOnlyPolicy.ps1), [Privacy.ps1](../../src/security/Privacy.ps1), [Common.ps1](../../src/common/Common.ps1) |
| Coletores | [System](../../src/collectors/System.ps1), [Storage](../../src/collectors/Storage.ps1), [Startup](../../src/collectors/Startup.ps1), [Performance](../../src/collectors/Performance.ps1), [Events](../../src/collectors/Events.ps1), [Advanced](../../src/collectors/Advanced.ps1) |
| Análise e pontuação | [Rules](../../src/analysis/Rules.ps1), [HealthScore](../../src/analysis/HealthScore.ps1), [Evidence](../../src/analysis/Evidence.ps1), [regras declaradas](../../rules/rules.json) |
| HTML e JSON | [HtmlRenderer](../../src/reports/HtmlRenderer.ps1), [CSS](../../templates/style.css), [esquema](../../schemas/diagnostic.schema.json), [PT-BR](../../locales/pt-BR.json), [EN](../../locales/en.json), [amostras](../../samples/README.md) |
| Integrações e testes | [contrato da skill](../../SKILL.md), [Claude](../../adapters/claude/README.md), [Codex](../../adapters/codex/AGENTS.md), [suíte offline](../../tests/Run.Tests.ps1), [fixtures](../../tests/fixtures) |

O Graphify gerou e consultou um mapa AST local de apoio. As conclusões foram conferidas nos arquivos de origem.

## Achados e correções

| Prioridade | Evidência | Correção e limite |
|---|---|---|
| P0 · carregamento e scanner | O CLI carregava auxiliares e coletores antes do gate. O scanner aceitava dot-sourcing sem conferir o alvo e comandos pelo prefixo de funções internas. Redirecionamentos e acesso dinâmico a membros estavam fora do filtro. | Gate antes dos auxiliares. Coletores restritos ao ramo real após consentimento. Manifesto explícito, funções declaradas, caminhos de carga literais e listas de comandos, parâmetros e membros. A análise AST continua dependente da integridade do ponto de entrada, scanner, shell e provedores. [Entrada](../../fixmypc.ps1) · [scanner](../../src/security/ReadOnlyPolicy.ps1) |
| P0 · consentimento e efeitos prévios | A expressão anterior já recusava `-Yes` sozinho no ramo real. A saída era criada antes da decisão e a expressão de resposta interativa aceitava prefixos. A suíte chamava o CLI real sem fixture para verificar a recusa. | A resposta precisa ser exata. O CLI valida a presença de `-Fixture` separadamente do conteúdo do argumento. A saída começa após validação e análise. Os testes negativos executam uma cópia com os seis coletores substituídos. Os adaptadores exigem consentimento para a execução específica. [CLI](../../fixmypc.ps1) · [testes](../../tests/Run.Tests.ps1) |
| P0 · escrita | O controle de escrita comparava prefixos textuais. O método de gravação substituía arquivos existentes. | Caminho absoluto em disco local, recusa de componentes ambíguos, fluxos alternativos e reparse points. Preflight de todos os nomes e abertura com `CreateNew`. Os arquivos herdam ACLs do destino. A validação por caminho ainda tem uma janela entre checagem e abertura. [I/O](../../src/common/Common.ps1) |
| P0 · HTML e JSON | O HTML recebia achados brutos e o caminho de saída. A célula de percentual preservava entrada inválida sem encoding. O sanitizador ignorava `PSCustomObject` e a exportação não incluía os achados que os adaptadores deveriam ler. | O renderizador aceita o documento sanitizado inteiro, com análise e nota. Encoding de valores em texto e atributos, sem links derivados dos dados, CSS local e CSP. JSON sanitizado inclui achados e cobertura. JSON interno exige opção explícita. Leitura e escrita UTF-8 com teto de 8 MiB por artefato e limite de profundidade. [Privacidade](../../src/security/Privacy.ps1) · [HTML](../../src/reports/HtmlRenderer.ps1) · [esquema](../../schemas/diagnostic.schema.json) |
| P0 · rede indireta | Authenticode inspecionava caminhos extraídos da inicialização e podia acionar a cadeia de confiança do Windows. A interface do cmdlet não expõe controle offline de revogação. | Authenticode real ficou em `not_collected`. A regra e o HTML continuam interpretando resultados sintéticos existentes. Pastas redirecionadas para rede e reparse points ficam fora da leitura de inicialização. A coleta de eventos omite mensagens brutas. [Advanced](../../src/collectors/Advanced.ps1) · [Startup](../../src/collectors/Startup.ps1) · [documentação do cmdlet](https://github.com/microsoftdocs/powershell-docs/blob/main/reference/7.7/Microsoft.PowerShell.Security/Get-AuthenticodeSignature.md) |
| P1 · resultado dos coletores | Os seis módulos chamavam `Add-FmpEvidence`, que não estava definida. O invólucro podia emitir resultados incidentais e marcar uma série com estados `error` como bem-sucedida. | Chamadas usam `New-FmpEvidence`, o invólucro retorna um único registro e distingue falha, sucesso e êxito parcial com base nos subchecks. Regressão executada com um bloco sintético. [Evidence](../../src/analysis/Evidence.ps1) |
| P1 · nota indisponível | A função de saúde retornava um número mesmo quando o estado era `unavailable`. O CLI formatava esse número como `N/100`. | Nota nula no JSON e estado sem número no HTML e CLI. Cobertura conta evidência, enquanto erro e acesso negado contam como tentativas. Deduplicação e teto produzem a mesma dedução nos itens detalhados e no total. [Pontuação](../../src/analysis/HealthScore.ps1) |
| P1 · falsos resultados | Contagens de sete dias entravam como recorrência recente. Canais vazios podiam causar erro de validação de estado. SMART indefinido, amostras incompletas e certos campos nulos ou ausentes viravam resultado conclusivo. | Filtros e estados conservadores, timestamps por ocorrência, distinção entre nível Crítico e Erro e cobertura limitada pelo estado dos canais. SMART com indicador desconhecido permanece inconclusivo. [Regras](../../src/analysis/Rules.ps1) · [coletor de eventos](../../src/collectors/Events.ps1) |
| P2 · instalação e exemplos | O adaptador Claude indicava uma pasta de outra integração. Exemplos usavam Bypass e o README documentava números da etapa anterior. | Caminhos da skill Claude atualizados, exemplos com a política efetiva e amostras sintéticas alinhadas ao pipeline. A licença MIT aguarda confirmação do proprietário antes de publicar. [Claude](../../adapters/claude/README.md) · [política](../readonly-policy.md) |

## Revisão das 22 regras

| Área | Regras e leitura da evidência |
|---|---|
| Armazenamento · 5 | `low_free_space` e `disk_space_critical` exigem a unidade de sistema identificada e percentual de 0 a 100. `disk_health_unhealthy` reconhece `Warning` e `Unhealthy`. `smart_predict_failure` exige um preditor booleano disponível. `disk_event_errors` registra ocorrências recentes de provedores de armazenamento, como histórico. |
| Eventos · 5 | `critical_recurring` conta somente nível Crítico na janela curta. `error_concentration` exige contagem comprovada para o mesmo provedor e ID. `whea_hardware` reconhece o nome de provedor com ou sem prefixo Windows. `unexpected_shutdown` limita a dupla contagem dos dois provedores. `bsod` exige o ID 1001 de provedor de BugCheck no canal System. WHEA, desligamentos e BSOD são históricos. |
| Desempenho · 3 | `cpu_sustained_high` exige o mínimo de amostras e descreve a janela curta. `ram_pressure` exige percentual e quantidade de memória coerentes. `commit_pressure` registra a leitura instantânea. |
| Inicialização · 2 | `high_count` usa o limiar de mais de 30 entradas e considera falhas de inventário. `unsigned_autostart` é informativa e requer evidência de assinatura. |
| Sistema · 4 | `w10_eol` consulta o retrato estático de versões Home/Pro com a data da auditoria. `long_uptime` usa uptime válido. `pending_reboot` exige estado de leitura e indicador booleano. `outdated_patch` exige uma data de hotfix conhecida e usa o inventário parcial de hotfixes como indício. |
| Segurança e dispositivos · 3 | `defender_disabled` exige estado explícito do Defender e inventário de AV disponível. `third_party_av` sinaliza registro, sem atestar proteção ativa. `devices_problem_codes` exige código informado pelo Windows. Idade de driver fica como metadado. |

Os pesos padrão continuam 30, 25, 20, 15 e 10 para armazenamento, eventos, desempenho, inicialização e SO. A cobertura e a confiança estão disponíveis no HTML e no JSON. O algoritmo aplica a maior penalidade por grupo causal e os tetos por categoria. Regras inconclusivas e verificações exclusivas da Completa não deduzem. Os limites e pesos continuam configuráveis. [Metodologia](../methodology.md)

## Coleta Completa e limites de homologação

- Eventos de segurança consultam somente a ocorrência 4625 no recorte previsto. Ausência válida vira zero. Acesso negado e erro mantêm a contagem indisponível. O teto é marcado para leitura como contagem mínima.
- Drivers são consultados para dispositivos com códigos de problema quando o conjunto está dentro do limite. A correspondência por ID, a disponibilidade das classes CIM e o comportamento em falha parcial ainda precisam de homologação.
- Defender e Security Center precisam de verificação com produto ausente, substituído e em modo passivo. O registro de antivírus equivale a inventário.
- Atualizações usam indicadores passivos de reinício e hotfixes já instalados. A pesquisa de pendências do Windows Update permanece `not_collected`.
- Confiabilidade depende do RAC e de seus provedores CIM. Verificar disponibilidade, ordenação e diferenças entre registros e métricas.
- Inventário de aplicativos usa chaves de desinstalação locais dos escopos disponíveis. Validar entradas sem propriedades opcionais, visões 32/64 bits e duplicatas.
- Assinaturas reais permanecem pendentes. Validar revogação, catálogos, timestamps e ausência de tráfego antes de reabilitar a coleta.

## Antes e depois

| Verificação | Antes | Depois |
|---|---|---|
| Suíte offline | 127/127 em PowerShell 5.1 e 7 após retirar a invocação negativa com coletores reais disponíveis. O relatório anterior alegava 128/128. | 181/181 nas duas versões. |
| Scanner AST | O conjunto anterior passava com zero violações, apesar das lacunas acima. | `-ValidateOnly` passou com 15 arquivos executáveis analisados e zero violações. Os snippets de teste fora da allowlist são rejeitados. |
| Fixture `low-disk` | 72/100 com penalidade por Erros classificados como recorrência Crítica. | 82/100. |
| Fixture `events-mixed` | 75/100. | 84/100. Esse 84 pertence a uma fixture com cobertura suficiente. |
| Fixture de demonstração | 72/100. | 82/100 e 100% de cobertura em ambos os modos. Seis achados na Completa e três na Simples. |
| Cobertura insuficiente | A estrutura permitia número com estado indisponível. | `degenerate` devolve `score: null` e exibe somente o estado. |
| Esquema JSON | Uma fixture degenerada tinha seis campos nulos fora do esquema. | 22 JSONs de saída validados com Draft 7 e formatos RFC 3339. Foram 10 fixtures em PowerShell 7 e a demonstração adicional em 5.1. |

As novas asserções cobrem consentimento exato, flags e falha de binding, ausência de fallback, criação exclusiva, caminhos malformados, fronteira HTML/JSON sanitizada, entrada XSS como texto, cobertura indisponível, deduplicação, tetos, arrays aninhados, nulos, Unicode e vários estados diagnósticos. A suíte usa o Windows PowerShell 5.1.26100.9818 e o PowerShell 7.6.9. A execução no 5.1 exigiu `-ExecutionPolicy RemoteSigned` somente no processo de teste.

O CLI verifica a estrutura de entrada e saída que o pipeline consome. O validador Draft 7 independente verificou o esquema publicado e todos os JSONs gerados. Um parser de HTML confirmou a CSP e a ausência de scripts, atributos executáveis, referências externas e caminho de saída no laudo sintético. A combinação original de nota com estado indisponível foi reproduzida no cálculo com dados sintéticos. O valor 84 citado para uma execução anterior no computador permanece sem verificação nesta etapa.

## Pendências para Gemini Hydrogen 4

1. Em VMs Windows 10 e 11 autorizadas para essa finalidade, testar cada coletor com usuário padrão, falhas de provedor, ausência de cmdlets e dados incompletos. Observar I/O e tráfego para avaliar efeitos indiretos.
2. Repetir testes de junctions e links, concorrência na saída, permissões herdadas e cenários de diretório compartilhado. A revisão offline não demonstra confinamento contra substituição concorrente de um diretório por outro processo com acesso de escrita.
3. Homologar formato e ordenação dos dados de eventos e RAC. Conferir o ciclo de vida da Microsoft por edição, programa ESU e data antes de atualizar a tabela integrada.
4. Validar o laudo em navegador e a integração instalada de Claude e Codex. Confirmar a licença MIT antes de publicar.

O ambiente retornou `Acesso negado` ao criar a junction sintética. A verificação lexical passou para caminhos relativos, UNC, traversal, caminhos de dispositivo e fluxos alternativos. A checagem de reparse points foi inspecionada no código e continua pendente de teste de integração.

**APROVADO COM RESSALVAS**

A classificação se aplica à próxima revisão de desenvolvimento. Publicação e auditoria real dependem de autorização e homologação próprias.
