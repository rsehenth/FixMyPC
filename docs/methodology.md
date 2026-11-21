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
