# Metodologia — estados, severidades e pontuação (v0.1.0)

## Estados das verificações

Cada regra termina exatamente em um estado:

| Estado | Significado | Efeito na pontuação |
|---|---|---|
| `pass` | Evidência suficiente e sem problema | Nenhum |
| `finding` | Problema ou condição de revisão identificado | Penaliza (quando a regra tem penalidade) |
| `unknown` | Dados inconclusivos | **Nunca penaliza; nunca prova saúde** |
| `unsupported` | Recurso não suportado neste ambiente | Excluído da cobertura |
| `access_denied` | Falta de permissão | Conta como tentativa; não penaliza |
| `not_collected` | Fora do escopo (com justificativa) | Excluído da cobertura |
| `error` | Falha técnica da coleta | Conta como tentativa; não penaliza |

## Severidades exibidas

- **Informativo** — contexto útil; nunca penaliza.
- **Atenção** — merece olhar; penaliza quando comprovada.
- **Recomendado revisar** — problema ou condição com evidência; penaliza.

Severidade, confiança e estado são conceitos distintos e são exibidos
separadamente em cada achado.

**Escala (FMP-05).** `Informativo` < `Atenção` < `Recomendado revisar`. Dentro de um
mesmo grupo de dedupe (mesma causa raiz), a regra de maior penalidade nunca tem
severidade inferior à de uma regra de menor penalidade: a prioridade visual não pode
contradizer a pontuação. Em empate de severidade, o achado de maior penalidade vem
primeiro. Por isso "< 5% livre" (penalidade 10), `Unhealthy` (12) e "5 ocorrências
críticas em 48 h" (10) são `Recomendado revisar`, no mínimo no nível das regras mais
leves dos seus grupos. O teste de regressão verifica a regra diretamente em
`rules/rules.json`.

## Princípios anti-falso-positivo

As regras v0.1.0 nunca afirmam que:

- programa desconhecido é suspeito (assinatura ausente ≠ malware);
- ocupação momentânea de CPU/RAM é defeito permanente (limitações declaradas);
- existência de eventos implica corrupção ou falha física atual;
- ausência de SMART significa disco saudável;
- eventos históricos indicam falha atual. As regras de recorrência usam
  ocorrências comprovadas nas últimas 48 h. WHEA, BugCheck e reinícios
  relatam histórico dos últimos 7 dias.

## Pontuação

Fórmula (FMP-01):

```
E        = categorias elegíveis nesta execução
nota     = round( 100 × Σ_{c∈E} (peso_c − dedução_c) / Σ_{c∈E} peso_c )
```

- Uma categoria é **elegível** somente se (1) existe ao menos uma regra-base
  (`modes` contém `"simple"`) com penalidade > 0 nessa categoria e (2) ao menos
  uma das suas verificações-base terminou em `pass` ou `finding` nesta execução.
  Caso contrário ela fica **fora da nota** (`eligible: false`,
  `excludedReason: no_base_rules | no_evidence`) e não contribui com pontos.
  Uma categoria sem evidência deixa de valer como "saudável".
- Pesos (configuráveis em `rules/rules.json`): Armazenamento 30, Eventos 25,
  Desempenho 20, Inicialização 15, Sistema 10. **Na v0.1.0 a Inicialização não
  tem regra-base penalizável** (todas as regras de inicialização são exclusivas
  da Completa e informativas). Por isso ela fica sempre fora da nota, e o peso
  elegível máximo é 85. O peso continua configurado para regras-base futuras.
- **Teto por categoria**: a dedução de uma categoria nunca excede seu peso.
- **Dedução máxima alcançável** com as regras atuais (após dedupe):
  Armazenamento 22/30, Eventos 25/25, Desempenho 4/20, Sistema 6/10. Com todas
  as regras-base em achado, a nota é round(100 × (85 − 57) / 85) = **33**. Nenhuma
  regra ou penalidade foi criada para forçar a nota a 0.
- **Limite por gravidade (riskGates)**: uma falha grave de armazenamento
  comprovada por regra-base (`storage.disk_health_unhealthy` com o veredito
  `Unhealthy` do próprio Windows, ou `storage.smart_predict_failure` com
  `PredictFailure=true`) define `riskLevel: critical` e limita a nota a
  `riskGates.critical.scoreCap` (**49**). O JSON registra `uncappedScore`,
  `scoreCap` e `capped`. Justificativa: essas duas fontes são o próprio sistema
  ou o firmware do disco declarando falha, com risco de perda de dados. 49 fica
  abaixo da metade da escala, então a nota não pode ser lida como saúde normal
  ou excelente. `Warning` não limita a nota (o risco fica `elevated`), porque
  o Windows também usa `Warning` para condições recuperáveis.
- **Grupos de dedupe**: regras que descrevem a mesma causa raiz
  (`storage.space`, `storage.health`, `events.recurrence`, `events.stability`)
  contam uma única vez — a maior penalidade do grupo.
- **A métrica-base é idêntica nos dois modos**: as regras com `"simple"` em
  `modes`. Regras exclusivas do modo Completa têm penalidade 0 e aparecem como
  "análise adicional".
- Achados informativos e override dinâmico (ex.: 1 único desligamento
  inesperado → informativo) são suportados pelo avaliador.

## Cobertura

- **Aplicáveis** são as regras-base fora dos estados `unsupported` e `not_collected`.
- **Cobertas** são as verificações com evidência suficiente (`pass` ou `finding`).
  `unknown`, `access_denied` e `error` contam como tentativas, sem aumentar a cobertura.
- O JSON e o HTML mostram cobertura global e contagens por categoria.
- A nota é indisponível abaixo de 35% de cobertura, sem categoria elegível, sem regras aplicáveis ou
  diante de falha total nos módulos-base de sistema, armazenamento, desempenho
  ou inicialização **que alimentem uma categoria pontuável**. A Inicialização não tem
  regra-base penalizável e fica fora da nota; portanto a falha desse módulo, por si só,
  não invalida uma nota calculada com as demais categorias (ela continua listada na
  Metodologia do relatório e a categoria segue "fora da nota"). Se a Inicialização
  ganhar uma regra-base, a falha do módulo volta a bloquear a nota. Nesses casos o JSON registra `score: null` e a interface
  mostra apenas o estado. Eventos entram pela cobertura das regras dos canais-base.
- Cobertura inferior a 60% ou qualquer verificação-base inconclusiva gera nota
  provisória. Os limites ficam em `rules/rules.json`.
- A nota-base usa as mesmas regras e o mesmo conjunto de canais de eventos nos
  dois modos. Falhas em módulos exclusivos do modo Completa não alteram a nota.

## Versão do algoritmo e nota provisória

- `healthScore.scoreAlgorithmVersion` identifica a fórmula: `2.0` = elegibilidade +
  renormalização + limite por gravidade (FMP-01); a versão `1` era a fórmula original da
  v0.1.0 (pesos como tetos). Calibrações de regras (severidade, penalidade) mudam a nota
  sem mudar a fórmula e são versionadas por `rules.json` (`version`). O campo é opcional
  no esquema, para que JSONs anteriores continuem válidos.
- Uma nota 100 **provisória** significa apenas "nenhuma dedução nas verificações
  concluídas". O cartão da nota mostra o número, o rótulo "Pontuação provisória" e a frase
  "Nenhum problema encontrado nas verificações concluídas (cobertura N%). Isto não prova que
  o computador está saudável." no lugar da legenda de escala. O JSON mantém `score`, `status`
  e `coveragePct` inalterados.

## Risco diagnóstico (separado da nota e da confiança)

Três conceitos independentes no JSON (`healthScore`) e no HTML:

| Campo | Pergunta que responde |
|---|---|
| `status` (`ok`/`provisional`/`unavailable`) | Há evidência suficiente para apresentar uma nota? |
| `confidence` (`high`/`medium`/`low`) | Quão completos são os **dados**? (não é saúde do PC) |
| `riskLevel` | O que os achados-base comprovados dizem sobre risco? |

- `critical`: há achado-base com `riskGate: critical` (ver acima).
- `elevated`: há achado-base não informativo com penalidade > 0.
- `none_detected`: nenhum achado desse tipo **nas verificações cobertas**.
- `undetermined`: nota indisponível e nenhum achado.

`riskReasons` lista as regras que definiram o nível. Achados exclusivos da
Completa nunca alteram o risco-base, o que mantém os modos comparáveis.
Exemplo: um disco `Unhealthy` com dados completos dá `status: ok`,
`confidence: high` e `riskLevel: critical`. Dado confiável não é PC saudável.

## Confiança

- `high` quando todas as verificações-base têm evidência.
- `medium` quando há lacunas, incluindo dados indisponíveis ou não coletados.
- `low` quando há erro nas regras-base, mais de 40% de verificações inconclusivas
  em relação às aplicáveis ou quando a nota está indisponível.

## Regras v0.1.0 (resumo)

| ID | Categoria | Severidade padrão | Penalidade | Limiar |
|---|---|---|---:|---|
| storage.low_free_space | storage | Recomendado revisar | 6 | < 10% livre |
| storage.disk_space_critical | storage | Recomendado revisar | 10 | < 5% livre |
| storage.disk_health_unhealthy | storage | Recomendado revisar | 12 | Windows reporta Warning ou Unhealthy |
| storage.smart_predict_failure | storage | Recomendado revisar | 8 | SMART prevê falha |
| storage.disk_event_errors | storage | Recomendado revisar | 6 | erros de disco em ≤ 48 h |
| events.critical_recurring | events | Recomendado revisar | 10 | ≥ 5 ocorrências de nível Crítico, ≤ 48 h |
| events.error_concentration | events | Recomendado revisar | 4 | ≥ 30 da mesma origem e ID, ≤ 48 h |
| events.whea_hardware | events | Recomendado revisar | 8 | qualquer WHEA em 7 d |
| events.unexpected_shutdown | events | Atenção | 6 | ≥ 2 em 7 d (1 → informativo) |
| events.bsod | events | Atenção | 8 | BugCheck em 7 d |
| perf.cpu_sustained_high | performance | Informativo | 0 | média ≥ 90% em ≥ 3 amostras (janela de ~4 s; observação, "CPU elevada durante a amostragem"; o id é mantido por compatibilidade) |
| perf.ram_pressure | performance | Informativo | 0 | < 10% e < 2 GB (pontual) |
| perf.commit_pressure | performance | Atenção | 4 | commit > 90% |
| os.w10_eol | os | Recomendado revisar | 6 | build passou do fim de suporte* |
| os.long_uptime | os | Informativo | 0 | > 60 dias |
| startup.unsigned_autostart | startup | Informativo | 0 | executáveis sem assinatura |
| startup.high_count | startup | Informativo | 0 | > 30 entradas do usuário (Run/RunOnce, pastas Inicializar, tarefas de logon); serviços automáticos do Windows não entram na contagem e ficam em `measured.services` |
| os.pending_reboot | os | Informativo | 0 | indicadores de reinício |
| os.outdated_patch | os | Atenção | 0 | hotfix > 365 dias |
| security.defender_disabled | os | Atenção | 0 | tempo real desligado e inventário de AV disponível sem 3º AV registrado |
| security.third_party_av | os | Informativo | 0 | 3º antivírus registrado |
| devices.problem_codes | os | Atenção | 0 | dispositivos com código de problema |

\* A data vem de um **retrato estático** embutido em `rules/rules.json`
(edições Home/Pro, conforme o ciclo de vida padrão da Microsoft). Build
fora da tabela → `unknown`, nunca penalidade. Confirme sempre no site oficial
da Microsoft.

## Coleta e privacidade

- Eventos usam os canais System e Application, níveis Erro e Crítico,
  janela de sete dias, teto de 2.000 eventos e 40 grupos por canal.
  A coleta mantém nível, horário, provedor e ID de evento. Um canal truncado
  não comprova ausência de ocorrências. Kernel-Power 41 e EventLog 6008
  podem descrever o mesmo reinício. A regra usa a maior contagem dos dois.
- CPU usa três leituras com intervalo de dois segundos via CIM. Uma série
  incompleta é inconclusiva. Pressão de RAM e commit descrevem a amostra.
- A verificação Authenticode fica em `not_collected` nas auditorias reais.
  A regra informativa continua aceitando evidências de fixtures existentes.
- Mensagens de eventos, argumentos de processos, seriais e chaves de produto
  ficam fora da coleta. O sanitizador mascara caminhos, contas e textos de erro.
  A versão interna é opcional. Inventários de software exigem revisão antes do envio.

## O que a pontuação NÃO é

Um auxílio de revisão. Não é diagnóstico médico do hardware, garantia de
funcionamento nem certificação de segurança. Toda decisão continua sendo do
usuário, com o técnico ou a IA que ele escolher.

## Diagnóstico orientado por sintoma (2.0, em desenvolvimento)

A pontuação responde "as regras de saúde encontraram algo?". O diagnóstico 2.0 responde outra pergunta: "existem
evidências relacionadas ao problema que a pessoa relatou?". Ele fica em `diagnosis` no JSON, é calculado por
`src/analysis/Diagnosis.ps1` depois das regras e **não altera a pontuação** (`scoreAlgorithmVersion` continua `2.0`).

### Modos e janelas

| Modo | Observação ao longo do tempo | Histórico de eventos | Histórico de inicialização |
|---|---|---|---|
| Rápida (`simple`) | não; só a amostra de ~4 s do coletor de desempenho (confiança baixa) | 7 dias | não lido |
| Completa (`full`) | `-ObserveSeconds` 15-300; padrão por sintoma: lento 60 s, geral 45 s, boot 30 s, travamento 30 s; uma leitura a cada 5 s; no máximo 61 leituras | 7 dias (30 dias para `crash`) | 60 dias, até 200 eventos |

A observação roda **antes** dos coletores de inventário, para que a carga da própria auditoria não domine a medição.
Ela tem orçamento de tempo (janela + 45 s): se os provedores ficarem lentos, para e marca `truncated`. Cada família
(CPU, memória, disco, processos) tem estado próprio; uma falha no meio mantém as leituras anteriores e marca `error`
ou `access_denied`, nunca `pass`. Ctrl+C cancela a execução; os resultados só são escritos no fim. Numa execução real, a
pasta de saída e o arquivo `run-reservation.json` já existem desde antes da coleta (consumo único da autorização).

### Fontes (somente leitura, todas na allowlist do scanner)

| Pergunta | Fonte | Cálculo |
|---|---|---|
| CPU | `Win32_PerfRawData_PerfOS_Processor` (`_Total`) | `100 × (1 − Δidle / ΔTimestamp_Sys100NS)` por intervalo |
| Processos | `Win32_PerfRawData_PerfProc_Process` (nome, PID, início, CPU, `WorkingSet`, `WorkingSetPrivate`, `PrivateBytes`, contadores de I/O) | núcleos = `ΔPercentProcessorTime / ΔTimestamp_Sys100NS`; % do computador = núcleos / processadores lógicos; I/O = `Δcontador / Δtempo real`; só nomes, sem linha de comando |
| Memória | `Win32_PerfRawData_PerfOS_Memory` | disponível (inclui cache e espera), comprometida/limite, `PagesInputPersec` por diferença / `Frequency_PerfTime` |
| Disco | `Win32_PerfRawData_PerfDisk_PhysicalDisk` (sem `_Total`, até 8 discos) | latência = `(ΔAvgDisksecPerRead / F) / ΔBase`; fila média = `ΔAvgDiskQueueLength / ΔSys100NS`; bytes/s por diferença |
| Inicialização | log `Microsoft-Windows-Diagnostics-Performance/Operational`, IDs 100-109 | campos lidos **pelo nome** no XML do evento (`BootTime`, `MainPathBootTime`, `BootPostBootTime`, `BootIsDegradation`, `FriendlyName`, `DegradationTime`); só o nome do arquivo, nunca o caminho |
| Reinícios | `System` Kernel-Power 41 (campos `BugcheckCode`, `PowerButtonTimestamp`), EventLog 6008, BugCheck/WER 1001, WHEA, SCM 7031/7034, Application Error 1000, Application Hang 1002 | contagem, dias distintos e último evento na janela |
| Armazenamento (histórico/saúde) | regras existentes `storage.disk_event_errors`, `storage.disk_health_unhealthy`, `storage.smart_predict_failure` | reaproveitadas; SMART inacessível vira "parcialmente desconhecido" |

As classes CIM brutas não dependem do idioma do Windows (os caminhos do `Get-Counter` dependem, por isso ele não é
usado). As classes formatadas também foram evitadas: a primeira leitura delas pode voltar zerada.

### Perguntas e limites (rules.json → `diagnosis.thresholds`)

| Pergunta (`id`) | "Sim" | "Parcial" | Cuidados registrados |
|---|---|---|---|
| `cpu_load` | ≥ 85% em pelo menos 50% das leituras | pico ≥ 85% sem sustentação | carga legítima (atualização, compilação, jogo, antivírus); só vale para a janela |
| `memory_pressure` | disponível < 1024 MB e < 10% **e** (paginação ≥ 100 páginas/s ou comprometimento ≥ 90%) | um desses sinais isolado | cache/espera contam como disponível; janela curta não demonstra vazamento |
| `storage_busy` | fila média ≥ 1 | fila máxima ≥ 4 | ocupado não é defeito |
| `storage_slow` | latência média ≥ 50 ms | média ≥ 20 ms ou p90 ≥ 50 ms | não há limite universal (NVMe, SATA, HD, disco virtual) |
| `storage_errors` | regra de erros de disco com achado | - | evento histórico não prova falha atual |
| `storage_health` | Windows/SMART informam falha | `partial_unknown` quando o SMART não pôde ser lido | é estado informado, não teste físico |
| `boot_history` | ≥ 2 inicializações degradadas ou mediana até a área de trabalho ≥ 60 s | 1 degradada ou mediana ≥ 40 s | componente só é citado se o Windows o apontou em mais de um evento; a contagem de itens de inicialização não explica a demora |
| `crash_history` | ≥ 2 reinícios inesperados em ≥ 2 dias, ou ≥ 2 telas azuis | qualquer evento isolado de instabilidade | Kernel-Power 41 não prova defeito de fonte; hipóteses: energia, botão, driver, temperatura |

Cada pergunta recebe uma **relevância** para o sintoma (matriz `diagnosis.relevance`), uma **confiança** (dados da
janela completa = alta; poucas leituras = média; leitura pontual = baixa), a **origem**, o **tipo de janela**
(`observation`, `history`, `snapshot`, `none`), limitações e explicações alternativas. Correlação na mesma janela:
quando há pressão de memória e o disco aparece ocupado ou lento, a hipótese "a paginação ocupa o disco" é registrada.

### Achados principais e conclusão

- Falhas de disco comprovadas pelas regras (`riskGate` crítico ou espaço crítico) entram sempre, mesmo fora do sintoma.
- Depois, respostas "sim"/"parcial" por relevância; "parcial" de relevância baixa fica só nos detalhes. Máximo de três;
  empates seguem a ordem fixa das perguntas. Nenhum achado é inventado quando não há evidência.
- Conclusão: `found` (há "sim" de relevância alta), `weak` (só sinais parciais), `none` (perguntas relevantes
  respondidas sem evidência) ou `insufficient` (menos de 50% das perguntas relevantes puderam ser respondidas).
- Próximos passos são informativos e verificáveis (repetir a medição durante o problema, Monitor de Confiabilidade,
  backup antes de qualquer providência, ferramenta do fabricante). Nunca há reparo automático.
- Inventário (antivírus, aplicativos, serviços, dispositivos) não gera achado por existir.

### Fase A: evidências por processo, eventos e horário do incidente

**Memória.** `workingSetMB` é a memória residente, `workingSetPrivateMB` é a parte residente privada e `commitPrivateMB`
(Private Bytes) é a memória privada comprometida. O campo legado `privateMB` continua sendo o Working Set privado e
`topMemory` continua ordenado por ele; `topCommit` ordena por memória comprometida. Valor ausente ou zero em
`PrivateBytes` vira `null`. Uma leitura alta nunca é chamada de vazamento.

**I/O.** Taxas e operações por segundo usam a diferença dos contadores cumulativos sobre a duração real entre amostras.
A identidade da instância é PID + início, então um PID reutilizado não mistura contadores. Contador reiniciado, ausente
ou intervalo inválido descarta só aquele intervalo (`ioInvalidIntervals`). Os contadores incluem arquivos, rede e
dispositivos, por isso a leitura é sempre de coincidência com disco ocupado, nunca de atribuição.

**Agrupamento.** `appGroups` soma as instâncias vivas **em cada leitura**, por nome do executável sem o sufixo `#n`
(`appGroupBasis = executable_name`). O pico é um total simultâneo real. O mesmo nome não prova o mesmo aplicativo, e os
grupos não devem ser somados às linhas por processo.

**Catálogo de eventos** (`events.catalog`, só na Auditoria Completa, canal `System`, 30 dias, até 60 com incidente
antigo, até 300 registros por provedor). Cada entrada é um par provedor + ID com níveis próprios; guarda só horário e
nível, nunca a mensagem.

| Área | Provedor e ID | Níveis |
|---|---|---|
| Vídeo | `nvlddmkm` 153; `Display` 4101 | 1-3 |
| Armazenamento | `disk` 7, 51, 153; `stornvme` 129; `storahci` 129; `Ntfs` 55; `Microsoft-Windows-Ntfs` 140 | 1-3 |
| Rede | `Tcpip` 4231, 4266 | 1-3 |
| Reinício inesperado | `Microsoft-Windows-Kernel-Power` 41; `EventLog` 6008 | 1-2; 2 |
| Inicialização e desligamento | `Microsoft-Windows-Kernel-Power` 109; `EventLog` 6005, 6006; `User32` 1074; `Microsoft-Windows-Kernel-General` 12, 13 | 4 |
| Relógio | `Microsoft-Windows-Kernel-General` 1, só com salto de 120 s ou mais | 4 |

Cada provedor tem consulta própria porque filtrar por um provedor não registrado gera erro; ele fica como
`provider_absent`, sem afetar os demais. A hora do registro mais antigo do log define `retention.coversWindow`: sem
cobertura da janela, a ausência de eventos vira **inconclusivo**, nunca "não".

**Horário do incidente.** `-IncidentAt` aceita `yyyy-MM-ddTHH:mm[:ss][Z|±hh:mm]`, `during-run` ou `unknown`, com
`-IncidentToleranceMinutes` (1-720, padrão 30). O coletor não interpreta linguagem natural: é o agente que converte
"ontem à noite" em horário e tolerância. Os dois valores entram no escopo do token de consentimento. Sem deslocamento,
vale o fuso local com as regras históricas de horário de verão: hora inexistente é recusada e hora repetida amplia a
busca em 60 minutos. A correlação é recusada (`unknown`) se o log não alcança o horário, se há evento com data futura
ou se o relógio foi alterado perto do incidente.

**Hipóteses.** Cada achado separa evidência observada, hipótese provável, evidência complementar, confiança, limitações
e próxima ação segura. Os pares de `diagnosis.correlation.pairs` em `rules.json` indicam proximidade no tempo, nunca
causa. Perguntas novas só existem quando seus dados foram coletados, e a pontuação não muda.

### Fases B e C: investigações especializadas e adaptativas

**Validado apenas por testes sintéticos.** Estas regras ainda aguardam a homologação supervisionada em VM.

Depois da triagem, `Select-FmpInvestigations` decide de forma determinística o que roda, a partir de um catálogo fechado
em `rules.json` (`diagnosis.investigations`). A execução é um `switch` de ids fixos; a IA não escolhe nem compõe consultas.

| Investigação | Categoria | Gatilho | Fonte | O que nunca guarda |
|---|---|---|---|---|
| `gpu_events` | H | sintoma `crash` ou evento gráfico | `System`: `nvlddmkm`, `amdkmdag`, `amdkmdap`, `atikmdag`, `igfx`, `igfxn`, níveis 1-3 | mensagem |
| `wer_events` | H | `crash`, evento gráfico ou histórico de falhas | `Application`, `Windows Error Reporting` 1001 | bucket, módulo, caminho, arquivos anexados, nome do aplicativo |
| `net_ports` | N | Tcpip 4231/4266 | `MSFT_NetTCPConnection` (`State`, `OwningProcess`), `MSFT_NetUDPEndpoint`, faixas dinâmicas | endereços e portas de conexões |
| `service_hosts` | P | `svchost` entre os maiores | `Win32_Service` (`Name`, `ProcessId`, `State`) | caminho e conta |
| `gpu_use` | P | evento gráfico | contadores brutos `GPUEngine` e `GPUAdapterMemory` | identificador do adaptador |
| `storage_reliability` | D | `crash` ou sinal de disco | `Get-StorageReliabilityCounter` | número de série |
| `confirm_peak` | C | resposta parcial em CPU, memória ou latência | segunda janela de 30 s, até duas famílias | — |

**Profundidade.** `standard` autoriza H, P e N, com até 45 s. `deep` acrescenta C e D, histórico de 60 dias e até 120 s
(teto de 180 s). Ela entra no escopo do token: um token `standard` não autoriza `deep`.

**Critérios de parada.** Cada id recebe uma decisão, no máximo dois níveis e dez execuções. Sem gatilho, categoria não
autorizada ou falta de orçamento, o item é registrado e não roda. Uma fonte que falha não é repetida.

**WER.** Uma falha é um `ReportId`. Registros seguintes do mesmo id são reenvios. Uma falha só é "nova" se o primeiro
registro está nas últimas 48 h e a leitura não foi truncada; caso contrário é "indeterminada". O horário é o da gravação.

**Discos.** O `N` de `\Device\HarddiskN` é comparado ao `Win32_DiskDrive.Index`. Só eventos desde a última inicialização
são associados com segurança ao disco atual; número inexistente vira "dispositivo não existe mais".

**Portas.** A ocupação é aproximada (conexões ativas sobre a faixa dinâmica). Três leituras indicam uma tendência
momentânea e não preveem esgotamento. O dono atual nunca é apresentado como responsável por um episódio passado.

**Hipóteses.** `supported` tem evidência coletada, `not_supported` teve fontes respondendo contra (não significa
descartada), `inconclusive` tem dados que não discriminam e `untested` não pôde ser verificada. Nenhum estado afirma causa.

### Limitações conhecidas do 2.0

- Nenhuma medição foi homologada em Windows real; os limites são pontos de revisão iniciais e podem precisar de ajuste.
- Os nomes de provedores AMD e Intel não foram confirmados em hardware real.
- A Fase A foi validada só com dados sintéticos. IDs de provedores clássicos (`disk`, `Tcpip`, `Display`, `nvlddmkm`)
  não constam em manifesto e dependem de validação em eventos reais.
- O log de inicialização costuma exigir administrador; sem ele a pergunta de boot fica `access_denied`.
- A janela observa só o período da auditoria; problemas intermitentes podem não aparecer. Por isso o sintoma "lento"
  pergunta se o problema está acontecendo (`-DuringProblem`) e sugere repetir a medição.
- Contadores de disco em máquinas virtuais, RAID ou Storage Spaces podem não refletir o disco físico.
- As durações informadas no pedido de autorização são estimativas a partir dos tempos fixos do código, não medições.
