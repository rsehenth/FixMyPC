# Etapa 4 — Redesign visual do laudo HTML (Claude Sonnet 5.5)

**Classificação: APROVADO COM RESSALVAS.**
A aprovação visual não equivale à homologação dos coletores Windows nem autoriza publicação.

## 1. Resumo

O laudo foi redesenhado como relatório técnico de auditoria: cabeçalho com o
banner oficial, resumo executivo com nota, cobertura e confiança separadas,
achados com todos os campos exigidos, cartões de hardware, medidores de uso
baseados em valores medidos, tabelas que empilham no celular e CSS próprio para
A4. Continua um único arquivo HTML, offline, **sem JavaScript**, com CSP
restritiva. Os nove assets existem em `assets/` e foram integrados.

Nenhuma auditoria real foi executada. Todo HTML veio de `tests/fixtures/*.json`
(dados sintéticos). Não foi usado `-AcceptReadOnlyPolicy` por mim; a suíte
existente já usa o modo `-Fixture` (sem coleta) e foi executada como estava.
Não foram alterados regras, pesos, limiares, contratos de coletores, política
somente leitura, consentimento, estados de evidência nem permissões (sem git no
workspace, esta afirmação se apoia no registro das edições feitas; os testes de
política AST passam).

## 2. Arquivos modificados

| Arquivo | Mudança |
|---|---|
| `templates/style.css` | reescrito (6,7 KB → 23,2 KB): tokens, layout, responsivo, impressão |
| `src/reports/HtmlRenderer.ps1` | reescrito (52,6 KB → 75,9 KB): estrutura, assets, ícones, resumo, medidores |
| `locales/en.json`, `locales/pt-BR.json` | +41 chaves cada (296 → 337), paridade mantida |
| `src/common/Common.ps1` | **correção mínima no núcleo** em `Get-FmpLocaleString` (ver §9) |
| `tests/Visual.Tests.ps1` | novo, 193 asserções; chamado por `Run.Tests.ps1` (+2 linhas) |
| `tests/Collector.Tests.ps1` | 1 asserção ajustada: `<td>4321</td>` → `<td data-label="…">4321</td>` |
| `tools/Optimize-Assets.ps1`, `tools/Render-Samples.ps1` | novos, **somente desenvolvimento** |
| `assets/optimized/**` | novo: variantes, `manifest.json`, payloads Base64 |
| `docs/visual-integration.md`, `docs/screenshots/` | novos |
| `samples/` | `demo-report.html` regenerado (nova arte), `demo-report.en.html`, `visual/*` |
| `CHANGELOG.md`, `samples/README.md` | atualizados |

Intocados: `assets/branding/*` e `assets/report/*` (originais; tamanhos conferem
com o manifesto), `src/analysis/*`, `src/collectors/*`, `src/security/*`, `rules/`,
`fixmypc.ps1`, `schemas/`.

## 3. Assets disponíveis e ausentes

| Asset | Original | Situação |
|---|---|---|
| `branding/fixmypc-logo.png` | 2172×724, RGBA | presente, integrado (cabeçalho de impressão) |
| `branding/fixmypc-icon.png` | 1254×1254, RGBA | presente, integrado (favicon e rodapé) |
| `report/fixmypc-report-banner.png` | 2172×724, opaco | presente, integrado (topo) |
| `report/fixmypc-overview.png` | 1254×1254, RGBA | presente, integrado (Resumo executivo) |
| `report/fixmypc-hardware.png` | idem | presente, integrado (Hardware e Windows) |
| `report/fixmypc-findings.png` | idem | presente, integrado (Principais achados) |
| `report/fixmypc-startup.png` | idem | presente, integrado (Inicialização) |
| `report/fixmypc-storage.png` | idem | presente, integrado (Armazenamento e desempenho) |
| `report/fixmypc-privacy.png` | idem | presente, integrado (Privacidade e próximos passos) |

**Nenhum asset ausente.** Não existe arte para Eventos, Verificações avançadas,
Limitações e Metodologia; essas seções ficam sem imagem (nada foi inventado).
O fallback em texto existe e é testado (asset ausente, vazio, truncado, não
imagem, injeção de caracteres, SVG, traversal, acima do limite, manifesto inválido).

## 4. Otimizações

Feitas em desenvolvimento por `tools/Optimize-Assets.ps1` (System.Drawing do
Windows PowerShell 5.1; nada instalado; o renderizador só lê texto).

| Chave | Original | Variante | Tamanho original | Variante | % |
|---|---|---|---|---|---|
| banner | 2172×724 PNG | 1440×480 **JPEG q88** | 1.533.533 B | 102.472 B | 7% |
| logo | 2172×724 PNG | 720×240 PNG RGBA | 787.171 B | 132.957 B | 17% |
| icon | 1254² PNG | 96² PNG RGBA | 1.598.649 B | 19.476 B | 1% |
| overview | 1254² PNG | 144² PNG RGBA | 1.258.731 B | 35.232 B | 3% |
| findings | idem | 144² | 1.115.691 B | 32.796 B | 3% |
| hardware | idem | 144² | 1.196.339 B | 37.215 B | 3% |
| storage | idem | 144² | 1.063.810 B | 30.667 B | 3% |
| startup | idem | 144² | 1.271.993 B | 37.240 B | 3% |
| privacy | idem | 144² | 944.166 B | 26.812 B | 3% |
| **Total** | | | **10.770.083 B** | **454.867 B** | **4,2%** |

Desvio consciente da preferência por PNG: o banner é opaco e cheio de
gradientes; reduzido para 1440 px ainda ocupava 1.059.182 B em PNG. Em JPEG
fica 10× menor. Logo e ícones continuam PNG com transparência (verificado:
tipo de cor 6 no cabeçalho IHDR). O renderizador aceita apenas `image/png` e
`image/jpeg`.

## 5. Comparativo antes/depois

| Item | Antes | Depois |
|---|---|---|
| HTML demo PT-BR | 32.237 B | 700.078 B (EN 696.670 B; limite 8 MiB) |
| Composição do HTML | CSS 6,7 KB + marcação | imagens Base64 ≈ 606 KB + CSS 23 KB + marcação ≈ 70 KB |
| Imagens | nenhuma | 9 `<img>` + favicon, todas `data:` |
| CSP | `default-src 'none'; style-src 'unsafe-inline'; …` | + `script-src 'none'`; `img-src data:` só quando há assets válidos |
| Seções | 15 `<details>` (fechadas por padrão, perdidas na impressão) | 10 seções sempre abertas com índice de âncoras |
| Nota | número + barra de cobertura | cartão com `82/100`, medidor, estado; cobertura e confiança à parte |
| Achados | linha de rótulos | cartão com título, severidade (texto + ícone), explicação, evidência, confiança, limitações, verificação sugerida |
| Armazenamento | tabela | medidores de uso por volume e RAM (valores medidos) |
| Tabelas no celular | rolagem horizontal | linhas empilhadas com `data-label` |
| Impressão | cartões soltos | A4, logo compacto, quebras controladas, cabeçalho de tabela repetido |
| Chaves de idioma | 296 | 337 |

Impacto do desempenho: o custo é o Base64 (+607 KB, +33% sobre os 455 KB
binários). A geração não decodifica nem processa imagem; a leitura é de 9
arquivos de texto pequenos.

Capturas (em `docs/screenshots/`): topo, resumo e achados em 1440, 1024, 768,
375 e 320 px; PT-BR vs EN; estados provisório e indisponível; páginas 1 e 3 da
impressão A4 (rasterizadas de um PDF real).

## 6. Resultados de testes

| Suíte | Resultado |
|---|---|
| `tests/Run.Tests.ps1` (integrada) | **194/194** (baseline da Etapa 3: 193; +1 = suíte visual) |
| `tests/Collector.Tests.ps1` | **85/85** (inalterada, 1 asserção de marcação ajustada) |
| `tests/Visual.Tests.ps1` (nova) | **193/193** |
| Scanner AST somente leitura | 15 arquivos, 0 violações (dentro da suíte A) |
| Idiomas | 337/337 chaves, todas as fixtures em PT-BR e EN sem chave faltando |

Cobertura da suíte visual: SHA-256, assinatura, dimensões e alfa dos assets
reais; HTML gerado de fixtures; presença das nove imagens; ausência de
`<script>`, manipuladores `on*`, `javascript:` e de qualquer URL http(s); CSP
campo a campo; limite de 8 MiB; escape de texto e atributos com conteúdo
malicioso (script, `onerror`, `onload`, iframe, `<style>`, aspas no id da
execução); Unicode (acentos, CJK, emoji) por round-trip em arquivo UTF-8;
campos vazios; nota provisória, indisponível e cobertura parcial; achados
(ordem, campos, âncoras); nome longo; imagens ausentes ou corrompidas;
semântica e acessibilidade estruturais; CSS de impressão e responsivo.

Aprovação visual é **separada** dos testes: foi feita por mim, por inspeção de
capturas, no Chromium do Playwright (§8). Não substitui revisão humana.

## 7. Qualidade visual e acessibilidade

Direção: dossiê técnico sóbrio. Azul-marinho `#0b2545`, azul técnico, ciano/teal;
verde só em estados "OK"; âmbar para atenção; vermelho só para "Recomendado
revisar". Fonte `system-ui` (resolve para Segoe UI Variable no Windows 11), sem
fontes remotas. Sem gradiente decorativo, brilho, sombra pesada nem transform;
raio de 8–12 px. Verificações do impeccable/no-slop: sem eyebrow, sem números de
seção, sem `border-left` colorido grosso, sem ícones Unicode (ícones SVG
desenhados num único traço), sem anel de progresso.

Honestidade dos dados:
- Nota 82 → `82/100`; provisória → âmbar tracejado + rótulo "Nota provisória" +
  aviso; indisponível → sem número e sem medidor.
- O medidor da nota nunca é verde. Cobertura 100% não pinta a nota de verde.
- Categoria sem evidência aparece hachurada ("Sem verificações aplicáveis" ou
  "Sem evidência utilizável"), nunca como "10 de 10 pts".
- Campos ausentes dizem "Indisponível"; nada foi preenchido.
- Barras de uso (volume, RAM) e amostras de CPU usam apenas valores medidos; não
  há limiar de cor inventado.
- Notas de que eventos são históricos, de contagem truncada (`+`), de que nome
  desconhecido não é perigo e de que a amostragem é pontual.

Contraste (calculado, WCAG): texto principal 16,3:1; secundário 9,0:1;
apagado 5,7:1; texto claro sobre azul-marinho 7,9–13,2:1; selos de severidade
6,2:1 (vermelho), 6,5:1 (âmbar), 5,3:1 (azul); mínimo geral 4,9:1 (teal em
teal claro). Tudo ≥ 4,5:1. Estado nunca depende só de cor: texto + ícone de
forma distinta (losango, triângulo, círculo).

Estrutura: `h1` único, dez `h2`, landmarks, link de pulo, `aria-labelledby`,
tabelas com `th scope`, medidores `aria-hidden` com o valor em texto, imagens
de seção decorativas, banner com `alt`. **Não** foram executados axe, leitor de
tela nem teclado real; só verificação estrutural por teste e inspeção.

## 8. Compatibilidade

Verificado: Chromium (Playwright) em 1440, 1024, 768, 375 e 320 px — sem rolagem
horizontal (`scrollWidth == clientWidth`) e as nove imagens carregadas;
PDF A4 gerado com `page.pdf` (11 páginas no demo completo; barras visíveis com
"gráficos de plano de fundo" desligado; rodapé "N / M" renderizado). Windows
PowerShell 5.1 (suítes e renderizador).

**Não verificado:** Edge e Chrome instalados, Firefox, Safari, PowerShell 7, modo
de alto contraste/`forced-colors`, tema escuro (não implementado), impressão real
numa impressora, DPI/zoom do Windows. Recursos modernos usados: `aspect-ratio`,
`:focus-visible`, `text-wrap`, `print-color-adjust`, e margin boxes de `@page`
(sem suporte, o rodapé "N / M" some; o rodapé padrão do navegador continua).

## 9. Segurança (CSP/XSS) e achados no núcleo

CSP final: `default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`.
`script-src` não foi relaxado. Sem `connect-src`, `frame-src` ou `font-src`
(herdam `'none'`). A suíte injeta conteúdo malicioso em nome de item de
inicialização, GPU, provedor de evento, id de módulo e id da execução, e confirma
que nada vira tag, atributo ou manipulador. Payload de asset com HTML em Base64,
`<script>` no meio do Base64, mime SVG e traversal no manifesto são rejeitados.

Observação do ambiente: o console do navegador mostrou erros de CSP
(`script-src`/`form-action` "alongside other source expressions" e chamadas a
`gc.kis.v2.scr.kaspersky-labs.com` bloqueadas). Eles vêm de um antivírus do
anfitrião que injeta script e reescreve a política **no navegador**; o arquivo
gerado tem a CSP correta (conferida por `grep` no HTML e pela suíte). Não houve
nenhum erro de console originado do laudo. Não carreguei a skill
`security-audit`/`security-and-hardening`; compensei com os testes acima, mas a
auditoria de segurança dedicada fica para a Etapa 5.

**Defeitos encontrados:**
1. *(corrigido, núcleo)* `Get-FmpLocaleString` convertia chaves em lista
   (`report.review.steps`, `report.recommendations.generic`,
   `report.methodology.notes`, `cli.policy.points`, `cli.review.steps`) em uma
   única string, fundindo todos os itens num parágrafo, no HTML e no CLI.
   Correção de 6 linhas, só quando não há valores de formatação; não toca em
   segurança.
2. *(corrigido, renderizador)* `(71,9%%)` na linha de memória comprometida;
   vazamento do texto `state.` para subseções ausentes; "Nenhum achado nesta
   seção" em tabelas vazias; duas colunas "Tipo" em discos; PID rotulado
   "Item"; MB e `%` de processos sem unidade.
3. *(não corrigido)* textos de `limitations` vêm das regras em inglês mesmo no
   laudo PT-BR (ex.: "date from the built-in lifecycle snapshot…"). É dado de
   `rules`/`Rules.ps1`, fora do escopo.

## 10. Qualidade da impressão

A4 com margens de 13/14/18 mm, logo compacto no lugar do banner, cartão de nota
em versão clara, achados/cartões/linhas sem corte, títulos sem ficar órfãos,
cabeçalho de tabela repetido, "N / M" no rodapé. Seções abertas (sem `<details>`),
então nada some no PDF. Pendências: o identificador da execução não fica em
cada rodapé (CSS estático não permite); está no `<title>` e na primeira página.
O demo completo gera 11 páginas.

## 11. Problemas pendentes

- Validação visual só no Chromium; sem Edge/Firefox/Safari/PS7 (§8).
- Sem axe/leitor de tela/teclado real; sem tema escuro nem `forced-colors`.
- Estados brutos do Windows ("Healthy", "Online", "Ready", "Running") e
  `limitations` de regras aparecem em inglês no PT-BR.
- Fixture com `lastSeen` anterior a `firstSeen` (DistributedCOM) é exibida como
  veio.
- No celular de 320 px o texto dentro do banner fica pequeno; o `h1` e a
  tabela de metadados carregam o conteúdo.
- `style-src 'unsafe-inline'` permanece (necessário ao `<style>` e às larguras
  das barras).
- `tools/` e `assets/optimized/` precisam entrar no pacote conforme o caso:
  `tools/` não; `manifest.json` e `embed/` sim (sem eles o laudo usa o fallback).
- `.impeccable/hook.cache.json` é cache do hook de design, criado pela sessão.
- A seção de eventos usa `Get-FmpEntries` na ordem dos dados; não há ordenação
  por recorrência.

## 12. Recomendações para a auditoria Claude Opus 5.5

1. Conferir `Common.ps1` (`Get-FmpLocaleString`) e o diff do renderizador contra
   a política somente leitura; confirmar que nenhum membro/comando novo entrou
   (o scanner passa, mas vale revisão independente).
2. Auditoria dedicada de CSP/XSS: avaliar trocar `style-src 'unsafe-inline'` por
   hash para o `<style>` e mover as larguras das barras para classes; testar com
   um fuzzer de strings nos campos de dados reais.
3. Rodar a suíte em PowerShell 7 e abrir os demos no Edge/Firefox; imprimir um
   PDF real no Windows 11 e comparar com as capturas.
4. Passar axe e leitor de tela (NVDA/Narrator) pelo `samples/demo-report.html`.
5. Decidir se o banner JPEG é aceitável ou se a política exige PNG estrito.
6. Traduzir os textos de `limitations` das regras e normalizar os estados do
   Windows, se o PT-BR deve ficar 100% localizado.
7. Homologar os coletores em Windows real (fora do escopo desta etapa).
