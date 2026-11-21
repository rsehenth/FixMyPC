# Etapa 7 — Finalização visual, marca e preparação para release

**Modelo:** Claude Sonnet 5.5 · **Workspace:** `<workspace>` · **Data:** 2026-11-20

## Classificação: **BLOQUEADO PARA DISTRIBUIÇÃO PÚBLICA — apto a seguir para revisão final apenas das partes não visuais**

A classificação pedida tem três níveis (aprovado / aprovado com ressalvas / bloqueado). O resultado é
**BLOQUEADO**, porque o item central da etapa, o **FMP-10, continua aberto**: nenhuma ferramenta de geração ou
edição de imagem estava disponível, e eu não improvisei arte. Todo o resto foi feito e testado (seções 3 a 9).

> Esta classificação **não autoriza publicação nem auditoria real**. Nada foi publicado, commitado, enviado ao
> GitHub nem empacotado. Nenhuma auditoria real foi executada, `-AcceptReadOnlyPolicy` não foi usado por mim e
> nenhum dado do Windows anfitrião foi consultado.

---

## 1. Situação do FMP-10 — **ABERTO (bloqueio específico dos assets)**

### Inspeção real dos nove originais (olhando as imagens, não os relatórios)

| Asset (original) | Logotipo de quatro painéis do Windows | Elementos que parecem veredito de saúde |
|---|---|---|
| `branding/fixmypc-logo.png` | **sim** (monitor) | escudo verde com check; lista com 3 checks verdes |
| `branding/fixmypc-icon.png` | **sim** (monitor) | escudo verde com check; lista com 3 checks verdes |
| `report/fixmypc-report-banner.png` | **sim** (monitor) | escudo + checks; anel com check no painel da direita; lista com checks |
| `report/fixmypc-overview.png` | **sim** | escudo; 3 checks; **medidor** verde/laranja com ponteiro |
| `report/fixmypc-hardware.png` | **sim, 3 ocorrências** (monitor, lupa) | escudo com check |
| `report/fixmypc-startup.png` | **sim** | escudo; três chaves ligadas em verde |
| `report/fixmypc-findings.png` | não | escudo com check; triângulo verde com check; barras vermelho/laranja/verde fixas |
| `report/fixmypc-storage.png` | não | escudo com check; **medidor** verde; barras verdes de "saúde" no disco |
| `report/fixmypc-privacy.png` | não | escudo com check; três checks verdes |

Resultado: **6 dos 9** têm o logotipo do Windows; **9 dos 9** têm arte que pode ser lida como "tudo certo".
As variantes otimizadas (`assets/optimized/**`) e os nove `embed/*.b64` são redimensionamentos fiéis dos
originais (SHA-256 do manifesto confere com cada payload), portanto herdam os mesmos problemas.

### Por que não substituí

- Não existe ferramenta de geração/edição de imagem nesta sessão (busca feita; só há navegador, shell e leitura de
  imagens).
- Retocar por código (System.Drawing) arte rasterizada gerada por IA exigiria apagar o logotipo, reconstruir o que
  o escudo cobre (cabo da lupa, borda do monitor) e redesenhar medidores. O resultado seria de qualidade baixa e
  pareceria remendo. O pedido proíbe explicitamente isso e proíbe borrar ou ocultar parcialmente o símbolo.
- Por isso o FMP-10 **não é declarado resolvido**, e nada nos assets foi alterado (originais, otimizados e `.b64`
  permanecem byte a byte como na etapa 6; o SHA-256 de cada `.b64` confere com `manifest.json`).

### O que fica pronto para quando houver a arte nova

- Passo a passo de rastreabilidade em `docs/visual-integration.md` §4.1: novos arquivos com sufixo `-v2`,
  antigos preservados, `tools/Optimize-Assets.ps1` apontado para os novos, SHA-256 novo no manifesto,
  `Visual.Tests.ps1` como confirmação.
- **Especificação da arte substituta** (preserva paleta navy/cyan/teal/verde, lupa, monitor e relatório):
  monitor com interface diagnóstica abstrata (painéis, barras e linha de pulso dentro da lupa, sem logotipo de
  terceiros); selo de inspeção **neutro** (escudo ou lupa em azul/teal, sem check verde); sem medidor com
  ponteiro; barras de "saúde" em azul único; verde apenas como acento de marca (traço do gradiente), nunca como
  sinal de aprovação.
- `distribution-manifest.json` registra o FMP-10 em `releaseBlockers`, para que o pacote não seja tratado como
  liberado.

### Comunicação visual (item 2 do pedido) — não resolvida pelos mesmos motivos

O banner e os ícones **ainda** trazem escudos verdes com check e medidores fixos. Isso é um defeito aberto,
não uma decisão: o indicador efetivo de saúde do laudo continua vindo apenas dos dados (`riskLevel`, nota,
cobertura, selos de estado), e o texto de estado nunca é substituído pela arte. Mitigação existente: o aviso
sintético, a nota provisória ("isto não prova que o computador está saudável") e o texto de risco ficam logo
abaixo do banner. Mitigação **não** é correção.

---

## 2. Identidade visual resultante

Inalterada em relação à etapa 6 (arte original). Efeitos colaterais desta etapa na apresentação, todos em CSS e
texto, sem tocar nos assets:

- Rodapé do laudo passa a ter o aviso de não afiliação (PT-BR/EN).
- Rodapé de impressão A4 localizado (antes: inglês fixo no CSS).
- Títulos de achados `h4` → `h3` (hierarquia correta).
- Lista de categorias da nota em coluna única no celular (corrige rolagem horizontal a 320 px).
- Suporte a `forced-colors`.

## 3. Verificações de marcas

| Verificação | Resultado |
|---|---|
| Logotipo do Windows nos assets | **presente** (6/9), ver §1 — FMP-10 aberto |
| Texto "Windows" no produto | nome/tagline `Windows Diagnostic & Audit Skill` e o texto `report.brand.product`: referência de compatibilidade, mas **o nome do produto contém "Windows"**. Não alterei (decisão do proprietário). Vai para revisão jurídica. |
| Declaração de não afiliação | adicionada: rodapé do laudo, rodapé de página impresso, `README.md`, `README.pt-BR.md`, `NOTICE.md` (EN e PT-BR) |
| Marcas de terceiros em elementos próprios do logotipo | nenhuma outra identificada na inspeção (apenas o Windows) |
| Uso de Windows como endosso | não: o texto diz "citada apenas para indicar compatibilidade" |

Texto adotado (EN): *Independent tool. Not affiliated with, endorsed by or sponsored by Microsoft. Windows is a
trademark of Microsoft Corporation, named here only to state compatibility.* A redação segue a recomendação da
auditoria; **não é parecer jurídico**.

## 4. Licenciamento

- `LICENSE` **não foi alterado** (texto-rascunho MIT, "FIX MY PC contributors").
- `README.md`, `README.pt-BR.md` e `NOTICE.md` agora dizem que a MIT **não foi confirmada pelo proprietário** e
  que a decisão está pendente. Antes, o README afirmava "MIT — veja LICENSE".
- `distribution-manifest.json` registra `LICENSE-PENDING` como bloqueio de release.

## 5. Alterações feitas (todas pontuais)

| Arquivo | Mudança |
|---|---|
| `src/reports/HtmlRenderer.ps1` | rodapé com `<span class="disclaimer">`; `@page @bottom-left` localizado injetado a partir de `report.print.footer` (com remoção de `"`, `\`, `<`, `>` e controles); título de achado `h3` |
| `templates/style.css` | removido rodapé fixo em inglês; `@media (forced-colors: active)`; estilo do `.disclaimer`; `.finding-head h3`; `.cat-list` em 1 coluna ≤ 640 px |
| `locales/en.json`, `locales/pt-BR.json` | `report.footer.disclaimer`, `report.print.footer` (417 chaves em cada idioma, paridade mantida) |
| `tests/Visual.Tests.ps1` | +5 asserções (forced-colors, rodapé localizado, não afiliação, sem `h4`/`h3` de achado, `.cat-list`) |
| `samples/*.html`, `samples/visual/*.html` | regenerados com `tools/Render-Samples.ps1` (só lê `tests/fixtures`) |
| `README.md`, `README.pt-BR.md`, `CHANGELOG.md`, `docs/visual-integration.md` | licença pendente, não afiliação, FMP-10, forced-colors, rodapé |
| **Novos** | `.gitignore`, `distribution-manifest.json`, `tools/Test-DistributionManifest.ps1`, `NOTICE.md`, este relatório, capturas `docs/screenshots/stage7-*` |

**Não alterados:** coletores, regras, pontuação, scanner AST, consentimento, JSON sanitizado, política somente
leitura, `LICENSE`, assets, diretório padrão de saída. A conformidade do scanner foi reconfirmada
(`-ValidateOnly`: 15 arquivos, nenhuma violação), inclusive para `HtmlRenderer.ps1` modificado.

## 6. Testes executados (todos offline, fixtures sintéticas; execução desta sessão)

| Comando | Resultado |
|---|---|
| `fixmypc.ps1 -ValidateOnly` | PASS — 15 arquivos analisados, nenhuma violação; 417 chaves por idioma; `rules.json` OK |
| `tests\Run.Tests.ps1` | **385 passaram, 0 falharam** (inclui as suítes aninhadas) |
| `tests\Collector.Tests.ps1` | **85 passaram, 0 falharam** |
| `tests\Visual.Tests.ps1` | **198 passaram, 0 falharam** (eram 193; +5 desta etapa) |
| `tools\Test-DistributionManifest.ps1` | PASS — todo arquivo classificado uma vez; nenhum arquivo proibido no pacote runtime |
| Integridade dos assets | 9/9: SHA-256 do payload decodificado = manifesto, bytes = manifesto, assinatura PNG/JPEG correta |
| Varredura dos 6 HTML de amostra | `<script>`: 0 · atributos `on*=`: 0 · `@import`: 0 · `url(`: 0 · URLs externas (fora dos `data:`): 0 · CSP idêntica à esperada em todos |

Registro honesto sobre a primeira execução: a suíte visual falhou uma vez no meu novo teste de rodapé (o próprio
comentário do CSS continha o texto procurado). Corrigi o comentário e repeti; os números acima são da execução
final. Nenhum teste existente foi enfraquecido ou removido.

`out\fmp-tests-*` continua sendo criado dentro do projeto pelas suítes (P3-04 do audit, inalterado). A pasta está
no `.gitignore` e em `neverShip`.

## 7. Tamanho do HTML

Maior arquivo gerado: **0,671 MiB** (`demo-report.html`); mínimo 0,646 MiB. Limite: 8 MiB. Variação causada por
esta etapa: ~ +1,4 KB por laudo (aviso, CSS `forced-colors`, rodapé de impressão).

## 8. Segurança CSP / XSS

- CSP no arquivo: `default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'` (inalterada).
- Sem JavaScript, sem recursos de rede, sem links gerados de dados.
- O texto injetado no CSS (`@page`) vem do arquivo de idioma do próprio produto, nunca dos dados da auditoria, e
  ainda assim passa por filtro de `"`, `\`, `<`, `>` e controles.
- A regra `Expected a local CSS template without markup...` continua valendo para o `style.css`, e o novo texto é
  acrescentado depois dela.
- **Achado de ambiente:** ao abrir o laudo no navegador desta máquina, o console reportou erros de CSP
  (`script-src ... 'none'` com outras fontes, `form-action ... connect-src`). A causa **não é o laudo**: o
  antivírus instalado (Kaspersky) reescreve a meta CSP no DOM e injeta um script (`gc.kis.v2.scr.kaspersky-labs.com`).
  O arquivo em disco está íntegro (conferido por leitura do arquivo: CSP original, 0 `<script>`). A própria CSP do
  laudo bloqueou as chamadas de rede do script injetado (`[FAILED] csp`). **Para a revisão independente:** inspecione
  os bytes do arquivo ou use um navegador sem esse antivírus; não conclua nada pela meta lida do DOM aqui.

## 9. Acessibilidade e responsividade

Navegador: Chromium do Playwright já instalado, servindo as amostras por `127.0.0.1` (um servidor estático
temporário, encerrado). O protocolo `file:` é bloqueado pela ferramenta.

| Item | Como foi verificado | Resultado |
|---|---|---|
| 320, 375, 768, 1024, 1440 px | 6 amostras × 5 larguras = **30 combinações**, `scrollWidth` vs `clientWidth` | **0 rolagens horizontais** (a 320 px havia 12 px de estouro na lista de categorias; corrigido) |
| Indicador `riskLevel` | classes e texto vistos em 6 amostras + 1 crítica sintética | `elevated`, `none_detected`, `undetermined`, `critical` renderizam, com texto (não só cor) |
| Aviso de nota crítica e "nota limitada a 49" | captura a 320 px (`stage7-en-320-critical-summary.png`) | legível, sem corte, texto completo |
| Nota provisória | captura a 320 px PT-BR | mensagem "isto não prova que o computador está saudável" visível; barra listrada âmbar |
| Nota indisponível | captura a 320 px EN | legível |
| `forced-colors` | emulação `forcedColors: active` a 1024 px, captura PT-BR crítico | barras visíveis (`Highlight`), selos com borda; **não** testado em Windows com tema real de alto contraste |
| Hierarquia de títulos | percorri `h1`–`h4` da amostra | havia salto h2→h4 nos achados; corrigido para h3; `h1` único |
| Textos alternativos | lista das 9 imagens | banner e logo com `alt` descritivo de marca (sem afirmar saúde); ícones de seção `alt=""` + `aria-hidden`; rodapé decorativo |
| Impressão A4, rodapé localizado | regras `@page` lidas do DOM em modo print | `@bottom-left` = "FIX MY PC · Ferramenta independente, sem afiliação à Microsoft" (PT-BR) e "… Independent tool, not affiliated with Microsoft" (EN); numeração mantida |
| Impressão, quebras de página | CSS de impressão não foi alterado; testes de texto existentes passam | **não verificado visualmente** nesta etapa |
| Contraste | tokens de cor não foram alterados nesta etapa; **não recalculei razões de contraste** | não verificado |
| Tabelas | sem mudança; empilham ≤ 640 px (já coberto por teste) | não revisadas de novo |

**Limitação importante da impressão:** gerei PDF A4 com Chromium, mas o ambiente não tem `pdftoppm`, então não pude
rasterizar as páginas para ver o rodapé de página desenhado. A evidência é a regra CSS analisada pelo navegador,
não a imagem da página.

### Capturas disponíveis (`docs/screenshots/`, só desenvolvimento)

`stage7-en-320-top.png`, `stage7-en-320-critical-summary.png`, `stage7-ptBR-320-provisional-summary.png`,
`stage7-en-320-unavailable-summary.png`, `stage7-ptBR-1024-forced-colors-summary.png`,
`stage7-print-a4-ptBR-p1.png` (emulação de mídia print, sem margens da página). As capturas anteriores da etapa 4
continuam em `docs/screenshots/` e **não** refletem o rodapé novo. As amostras críticas
(`critical.*.html`) foram geradas apenas num diretório temporário a partir de uma cópia da fixture sintética com um
disco marcado `Unhealthy`; **não** foram adicionadas a `samples/`.

## 10. Manifesto de distribuição (sem publicar)

`distribution-manifest.json` + `tools/Test-DistributionManifest.ps1`. Cada arquivo do repositório pertence a
**exatamente um** grupo; o verificador falha se houver arquivo sem classificação, padrão que não casa com nada ou
arquivo proibido dentro do pacote.

| Grupo | Conteúdo | Tamanho |
|---|---|---|
| `runtime` (instalar e executar) | `fixmypc.ps1`, `SKILL.md`, READMEs, `NOTICE.md`, `LICENSE` (pendente), `CHANGELOG.md`, `src/*`, `rules/rules.json`, `locales/*.json`, `templates/style.css`, `schemas/diagnostic.schema.json`, `assets/optimized/manifest.json`, `assets/optimized/embed/*.b64`, `adapters/*`, `docs/{readonly-policy,methodology,visual-integration}.md` | **1,13 MB** |
| `development` | `tests/*`, `tools/*`, `samples/*`, `docs/reviews/*`, `docs/screenshots/*`, `docs/homologation-plan.md`, `IMPLEMENTATION-REPORT.md`, `assets/branding/*`, `assets/report/*`, `assets/optimized/{branding,report}/*`, `.gitignore`, o próprio manifesto | 20,3 MB |
| `neverShip` | `.playwright-mcp/*`, `.impeccable/*`, `.commandcode/*`, `out/*` | 7,5 MB |

**Excluídos do pacote público:** relatórios internos e evidências das revisões (`docs/reviews/*`, incluindo
`opus-5.5-evidence`), capturas, logs de navegador (com URLs de sessão do antivírus), caches de agentes (com caminho
absoluto), saída de testes (`out/`), originais pesados (~10 MB de PNG) e arquivos de desenvolvimento.
`docs/visual-integration.md` fica no pacote por ser documentação de uso, mas cita `tools/`, que não vai junto.

`.gitignore` cobre: `out/`, `report.html`, `diagnostic-*.json` (os demos `demo-*` seguem rastreados), `*.log`,
saídas do Playwright, caches de agentes (`.claude/`, `.codex/`, `.commandcode/`, `.impeccable/`, `.cursor/`,
`.gemini/`, `.agents/`, `graphify-out/`, `.context-mode/`…), temporários, segredos (`.env*`, `*.pem`, `*.pfx`,
`*.key`, `credentials.*`…) e pacotes locais (`dist/`, `*.zip`…).

**Limites:** `.gitignore` só funciona dentro de um repositório git (esta pasta ainda não é um); o verificador não
varre o *conteúdo* dos arquivos atrás de dados pessoais, só nomes. O pacote `runtime` ainda inclui os `.b64`
com o logotipo do Windows (FMP-10).

## 11. Pendências P3 (não tratadas aqui, por decisão do pedido)

Tratadas parcialmente: **P3-03** (`.gitignore` e manifesto feitos; o `OutDir` padrão dentro da pasta da skill
**não** mudou), **P3-14** (rodapé localizado e `forced-colors` feitos), **P3-15** (banner neutro: **não**, ver FMP-10).
Intactas: P3-01, 02, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13 e o filtro dos códigos 22/45 do P3-15.

## 12. Riscos de publicação

1. FMP-10 aberto: distribuição com logotipo do Windows e escudos verdes é risco de marca e de comunicação.
2. Licença MIT sem confirmação do proprietário.
3. Nome do produto contém "Windows" e precisa de revisão jurídica; o texto de não afiliação não substitui isso.
4. `OutDir` padrão dentro da pasta da skill/repositório do usuário (mudança exige política de caminhos própria).
5. Esta pasta não é um repositório git: o `.gitignore` e o manifesto ainda não foram exercitados num commit real.
6. Rodapé de página impresso e `forced-colors` sem confirmação visual em ambiente real.

## 13. Limitações desta etapa

- Sem geração/edição de imagem: FMP-10 e a neutralização dos ícones permanecem.
- Impressão: só a regra CSS foi comprovada; páginas não foram rasterizadas.
- Contraste de cores não recalculado; alto contraste só por emulação do navegador.
- Navegador desta máquina tem antivírus que altera a meta CSP no DOM (ver §8).
- Capturas só a 320 px, 1024 px (forced-colors) e print; 375/768/1440 foram verificados por métrica de overflow, não por inspeção visual.

## 14. Requisitos para a revisão independente

1. **Arte nova** dos nove assets (conforme §1), regenerada com `tools\Optimize-Assets.ps1`, com `source` e SHA-256 novos
   no manifesto, e confirmação visual de que não há logotipo de terceiros nem sinais de aprovação fixos.
2. Decisão do proprietário sobre a **licença** e sobre o **nome do produto**; revisão jurídica do texto de não afiliação.
3. Rodar `Run`, `Collector`, `Visual`, `-ValidateOnly` e `Test-DistributionManifest.ps1` **num clone limpo**.
4. Conferir a CSP pelos **bytes do arquivo**, não pelo DOM de um navegador com antivírus que injeta scripts.
5. Imprimir (ou salvar em PDF) um laudo PT-BR e um EN e olhar as páginas: rodapé, quebras, barras.
6. Testar com tema real de alto contraste do Windows.
7. Decidir o destino do `OutDir` padrão numa etapa própria (política de caminhos e consentimento).
8. Só então considerar release; esta etapa não cria release, tag nem publicação.
