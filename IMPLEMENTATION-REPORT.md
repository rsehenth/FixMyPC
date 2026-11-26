# Relatório Técnico de Implementação — FIX MY PC v0.1.0

**Modelo responsável:** GLM 5.3 · **Data:** 2026-11-20 · **Destino da revisão:** GPT Sol 6.2

---

## 1. Estrutura criada

```text
fixmypc/
├── SKILL.md                        # contrato do agente (frontmatter + corpo)
├── README.md / README.pt-BR.md     # documentação de usuário (EN/PT-BR)
├── CHANGELOG.md · LICENSE (MIT)
├── IMPLEMENTATION-REPORT.md        # este relatório
├── fixmypc.ps1                     # único ponto de entrada auditado
├── src/
│   ├── common/Common.ps1           # utilitários (JSON, escaping, locale, valores)
│   ├── security/ReadOnlyPolicy.ps1 # scanner AST da política somente leitura
│   ├── security/Privacy.ps1        # sanitização do JSON
│   ├── analysis/Evidence.ps1       # runner de coletores + evidências
│   ├── analysis/Rules.ps1          # 22 regras determinísticas
│   ├── analysis/HealthScore.ps1    # pontuação 0-100
│   ├── collectors/                 # System, Events, Startup, Performance, Storage, Advanced
│   └── reports/HtmlRenderer.ps1    # relatório HTML (zero JS)
├── rules/rules.json                # pesos, limiares, tabela de ciclo de vida
├── locales/pt-BR.json · en.json    # ~250 chaves cada, paridade validada
├── templates/style.css             # CSS do relatório (local, sem CDN)
├── schemas/diagnostic.schema.json  # JSON Schema draft-07
├── adapters/claude/README.md · codex/AGENTS.md
├── tests/Run.Tests.ps1 + fixtures/ (10 fixtures + snippets proibidos)
├── docs/readonly-policy.md · methodology.md
└── samples/                        # demo sintética (report + JSONs + README)
```

## 2. Testes executados e resultados

**Suíte offline `tests/Run.Tests.ps1`: 128 asserções, 128 passaram, 0 falharam**
(PowerShell 5.1.26100, máquina Windows real apenas como *executor* dos testes —
nenhum coletor consultou o sistema; todos os cenários vêm de fixtures).

Cobertura dos testes:

- **Política somente leitura (16 asserções):** o projeto inteiro passa na
  varredura AST; 13 snippets proibidos (escrita de registro, serviços,
  `Invoke-Expression`, `Invoke-RestMethod`, `Win32_Product`, `reg add`,
  `net stop`, `Start-Process`, `Set-ExecutionPolicy`, `CreateSubKey`, `Kill()`,
  `& $var`, `powercfg /energy`, `WebClient`) são todos detectados; invocação
  dinâmica rejeitada.
- **Utilitários (9):** acesso null-safe, escape HTML, formatação pt-BR,
  JSON malformado sem exceção.
- **Privacidade (12):** redação de perfil/IP/e-mail/GUID/credencial/conta,
  preservação de `LocalSystem`, sanitização não altera o documento interno.
- **Análise e pontuação (66):** as 10 fixtures sintéticas cobrem Windows 11
  saudável (100/ok), Windows 10 sem suporte (94/provisório), disco crítico com
  dedupe de grupos (72), picos de CPU/RAM (92; RAM informativa, sem linguagem
  de problema crônico), eventos mistos com teto de categoria 26→25 (75),
  sem administrador (100/**provisório** — dado insuficiente não tranquiliza),
  muitos itens de inicialização e sem assinatura (100; severidade
  informativa), modo Completa sem penalizar a métrica-base (100), fixture
  degenerada com XSS/unicode/nulls (indisponível, sem exceção), demo completa
  (72) e cenário "tudo errado" (pontuação >0, <60, deduções limitadas).
- **HTML (12):** doctype/charset, banner sintético, zero `<script>`, zero
  recursos externos (`src=`/`href=` http), XSS escapado (`&lt;script&gt;`, sem
  `href="javascript`), unicode preservado, token redigido no render.
- **i18n (4):** paridade total de chaves pt-BR↔en, toda regra com
  title/detail/humanCheck nos dois idiomas, fallback honesto.
- **CLI em processo real (8):** fixture→exit 0 com os três artefatos gerados,
  `privacy.sanitized=true`, `run.synthetic=true`, `-ValidateOnly` exit 0,
  execução sem consentimento → **exit 3** (bloqueada).

`-ValidateOnly` também passou (14 arquivos varridos, 0 violações).

## 3. Classificação por componente

| Componente | Classificação |
|---|---|
| Política somente leitura (scanner AST + gate + testes) | **Implementado e testado** |
| Coletores System/Events/Startup/Performance/Storage | **Implementado, não validado no Windows real** |
| Coletor Advanced (modo Completa) | **Implementado, não validado no Windows real** |
| Pipeline de evidências (timing, sub-checks, limitações) | **Implementado e testado** (com fixtures) |
| Regras (22) e limiares | **Implementado e testado** (fixtures) |
| Pontuação (pesos, tetos, dedupe, cobertura, confiança) | **Implementado e testado** (fixtures) |
| Sanitização/privacidade | **Implementado e testado** |
| Relatório HTML (14 seções, zero JS, impressão A4) | **Implementado e testado** (render + asserções) |
| i18n pt-BR/en + fallback | **Implementado e testado** |
| Interface CLI interativa (prompts) | **Parcial** — fluxo implementado; prompts não exercitáveis no harness não interativo (código segue o mesmo caminho validado por parâmetros) |
| SKILL.md + adaptadores Claude/Codex | **Implementado, não validado com agente real** |
| JSON Schema | **Implementado** (documentação para consumidores; sem validador embutido) |
| Testes offline | **Implementado e executado** (128/128) |
| Relatório demo sintético | **Implementado** (`samples/`, banner de dados sintéticos) |
| Auditoria real nesta máquina | **Bloqueado por política** (ver §7) |
| Pesquisa online de softwares | **Não implementado** — opt-in por design; sem infraestrutura de rede na skill, a rede é banida. Interface/contrato não construídos (nada simulado) |

## 4. Funcionalidades realmente implementadas (resumo)

Dois modos de auditoria; coleta passiva com filtros na origem (eventos
Erro/Crítico de 7 dias, teto de 2000/log, agrupamento por provedor+ID com
recorrência e amostra); inventário de inicialização (Run/RunOnce 64/32 bits,
pastas Startup, tarefas de logon, serviços automáticos — só metadados);
amostragem curta de CPU (3×2 s, contadores CIM independentes de idioma), RAM,
commit, pagefile, top processos; volumes/discos com saúde reportada pelo
Windows; SMART só como previsão de falha (ausência = inconclusivo); modo
Completa com dispositivos problemáticos, drivers dos dispositivos com problema,
Defender, AV de terceiros, reinicialização pendente (indicadores de registro),
hotfixes recentes, aplicativos por chaves de desinstalação (nunca
`Win32_Product`), assinaturas Authenticode (teto 40). Análise com estados
explícitos, severidades, confiança, limitações e verificação humana por achado;
pontuação explicável com pesos/tetos/dedupe/cobertura; sanitização em duas
camadas; relatório HTML autossuficiente em pt-BR/en; CLI com gate de
compliance, consentimento, progresso por módulo e caminhos de revisão.

## 5. Recursos não implementados / parciais

- **Pesquisa online de softwares (§11):** não implementada — a política bane
  rede na skill; não há interface falsa nem simulação. Registrar como roadmap
  (opt-in explícito, fora do processo de coleta).
- **Tabela de atributos SMART detalhada:** não interpretada (apenas previsão
  de falha binária + motivo).
- **Destinos de atalhos `.lnk`:** não resolvidos (evita COM do shell);
  registrado como limitação no coletor e no relatório.
- **Consultas ao Windows Update:** deliberadamente `not_collected` com
  justificativa no JSON (COM WU inicia atividade do agente/rede).
- **Monitor de Confiabilidade:** consultado no modo Completa, mas o RAC é
  frequentemente desabilitado → estado `unsupported` honesto.
- **Validação do JSON contra o Schema em runtime:** não embutida (o Schema é
  para consumidores; os testes fazem asserções estruturais).
- **Prompts interativos:** não exercitáveis no ambiente de testes (sem TTY);
  mesma lógica validada via parâmetros.

## 6. Limitações técnicas e riscos identificados

1. **Amostragem pontual:** 6 s de CPU não provam comportamento crônico — as
   regras declaram a limitação e a RAM é informativa por design.
2. **Retrato estático do ciclo de vida do Windows:** datas podem ficar
   desatualizadas; builds ausentes → `unknown`; o achado recomenda confirmação
   externa.
3. **`Get-AuthenticodeSignature`:** a validação de cadeia é feita pelo Windows
   e pode envolver verificações de revogação on-line do próprio SO (atividade
   do sistema, não da skill); documentado.
4. **Scanner estático:** cobre o código do projeto; não é prova formal contra
   todos os construtos dinâmicos (sem `Invoke-Expression`/`Add-Type`/COM a
   superfície é pequena). Detalhes em `docs/readonly-policy.md`.
5. **WOW6432Node:** em PowerShell de 32 bits a visão de 64 bits do registro não
   é acessível; limitação registrada quando aplicável.
6. **Coletores não validados em hardware real** — erros de campo (nomes de
   classes CIM, mensagens de exceção localizadas) podem diferir; o design
   degrada para estados `error`/`unknown` por sub-verificação, mas a validação
   real é o próximo passo crítico.
7. **Ocorrência durante o desenvolvimento:** um erro de design no parâmetro
   `-Yes` (que concedia consentimento implicitamente) fez o teste de CLI
   executar **uma auditoria real somente leitura nesta máquina de
   desenvolvimento** (84/100, saída em %TEMP%, arquivos apagados em seguida).
   A falha foi corrigida (`-Yes` nunca autoriza coleta real; apenas
   `-AcceptReadOnlyPolicy` ou consentimento interativo) e há teste que prova o
   bloqueio (exit 3). Registro mantido por transparência.
8. **PS 5.1:** todo o código é ASCII-only e testado no 5.1; PowerShell 7 não
   estava disponível no ambiente (compatibilidade esperada, não executada).

## 7. Conformidade com a política somente leitura

- **Verificável e verificado:** gate AST pré-execução (14 arquivos, 0
  violações), allowlist por comando/parâmetro, lista de proibidos explícitos,
  métodos .NET banidos, varreduras de `Win32_Product`/rede/comandos nativos de
  escrita, rejeição de invocação dinâmica, papéis por arquivo (coletores sem
  escrita), escrita de artefatos restrita a diretório autorizado via
  `Assert-FmpOutputPath`.
- **Nada de:** `Win32_Product`, `powercfg /energy`, `perfmon /report`,
  reparos, elevação, rede, mudança de política de execução persistente.
- **Separação coleta × artefatos:** coletores não chamam nenhuma função de
  escrita; só o entry point e o renderizador escrevem.
- **Trilha de auditoria:** inventário estático de comandos por módulo no JSON
  e na seção Metodologia do relatório.
- Durante os testes, nenhum coletor foi executado contra o sistema (apenas a
  ocorrência do item 7, discutida acima, e corrigida).

## 8. Estado do sistema de pontuação

Implementado, determinístico e testado: parte de 100; penaliza só `finding`
com penalidade > 0; tetos por categoria (30/25/20/15/10 configuráveis em
`rules/rules.json`); dedupe por grupo de causa raiz; regras do modo Completa
não entram na métrica-base; `unknown`/`access_denied`/`unsupported`/
`not_collected`/`error` nunca deduzem; cobertura exclui inconclusivos;
status `ok` só com cobertura 100% e zero inconclusivos — senão
"Provisória"/"Indisponível"; penalizações explicadas item a item no relatório;
texto de "não é diagnóstico/garantia/certificação" em todos os relatórios.

## 9. Qualidade e segurança dos artefatos

- **HTML:** zero JavaScript, CSS local embutido, CSP `default-src 'none'`,
  todo valor dinâmico por `HtmlEncode` (incluindo atributos), URLs de dados
  nunca viram links, responsivo, impressão A4, contraste acessível, banner de
  dados sintéticos quando aplicável. Testes provam ausência de `<script>`,
  `href="javascript`, recursos externos.
- **JSON:** serialização normalizada (datas ISO, profundidade/tamanhos com
  teto), `schemaVersion`, duas variantes (interna e sanitizada com contagem de
  redações e notas de privacidade).
- **Reprodutibilidade:** mesma entrada → mesma análise/pontuação (regras
  determinísticas, sem rede, sem relógio nas decisões exceto janelas de
  eventos ancoradas em `run.finishedAt`).

## 10. Pronto para revisão pelo GPT Sol 6.2

- Código completo e comentado nos pontos não óbvios; `SKILL.md` conforme o
  padrão de skills (nome/diretório, frontmatter, corpo imperativo).
- Sugestões de foco da revisão:
  1. Revisar os limiares das 22 regras contra falsos positivos em máquinas
     reais (principal risco pendente, pois os coletores não rodaram em
     hardware real);
  2. Auditoria independente do `ReadOnlyPolicy.ps1` (é o componente de
     segurança central);
  3. Rodar `-ValidateOnly` + `-Fixture` + uma auditoria real autorizada em
     máquina de teste para validar coletores;
  4. Revisar a UX do relatório (estrutura/tom) e a completude do SKILL.md
     para agentes;
  5. Avaliar se a política de `-ExecutionPolicy Bypass` por processo é
     aceitável para o público-alvo ou se prefere instrução de unblock.

## 11. Como reproduzir a validação

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run.Tests.ps1   # 128 asserções
powershell -NoProfile -ExecutionPolicy Bypass -File fixmypc.ps1 -ValidateOnly
powershell -NoProfile -ExecutionPolicy Bypass -File fixmypc.ps1 `
  -Fixture tests\fixtures\demo-synthetic.json -Mode full -Language pt-BR `
  -OutDir samples -Yes
```

Nenhum commit foi criado; nenhum repositório remoto foi usado; nenhuma
auditoria real foi executada além da ocorrência documentada no §6.7.
