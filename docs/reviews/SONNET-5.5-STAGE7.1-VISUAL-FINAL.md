# Etapa 7.1 — Identidade v2 integrada e polimento final do laudo HTML

**Modelo:** Claude Sonnet 5.5 · **Workspace:** `<workspace>` · **Data:** 2026-11-20

## Veredito: **APROVADO PARA REVISÃO INDEPENDENTE** (com as ressalvas das seções 14 e 15)

O FMP-10 está **resolvido do ponto de vista visual e técnico**. Licença MIT e revisão jurídica do nome do produto
**continuam pendentes**, e este veredito **não autoriza publicação nem auditoria real**. Nada foi publicado,
commitado, etiquetado ou empacotado. Nenhuma auditoria real foi executada, `-AcceptReadOnlyPolicy` não foi usado por
mim e nenhum dado do Windows anfitrião foi consultado.

---

## 1. Mapeamento dos nove assets v2

O `FIX-MY-PC-v2-assets.zip` estava na raiz do projeto (não extraído). Listei as entradas (sem caminhos suspeitos),
extraí numa pasta nova fora do projeto, e conferi os nove SHA-256, tamanhos e dimensões contra o `SHA256SUMS.json`
do pacote: **9/9 conferem, nada faltou**.

| Chave | Fonte v2 (no projeto) | Dimensões | Variante embutida |
|---|---|---|---|
| banner | `assets/report/fixmypc-report-banner-v2.png` | 2172×724, RGB opaco | `assets/optimized/report/…-v2.jpg`, 1440×480 |
| logo | `assets/branding/fixmypc-logo-v2.png` | 2172×724, RGBA | `assets/optimized/branding/…-v2.png`, 720×240 |
| icon | `assets/branding/fixmypc-icon-v2.png` | 1254×1254, RGBA | 96×96 |
| overview | `assets/report/fixmypc-overview-v2.png` | 1254×1254, RGBA | 144×144 |
| findings | `assets/report/fixmypc-findings-v2.png` | 1254×1254, RGBA | 144×144 |
| hardware | `assets/report/fixmypc-hardware-v2.png` | 1254×1254, RGBA | 144×144 |
| storage | `assets/report/fixmypc-storage-v2.png` | 1254×1254, RGBA | 144×144 |
| startup | `assets/report/fixmypc-startup-v2.png` | 1254×1254, RGBA | 144×144 |
| privacy | `assets/report/fixmypc-privacy-v2.png` | 1254×1254, RGBA | 144×144 |

**Arte antiga removida, conforme sua ordem de hoje.** Apaguei os 9 originais antigos, as 9 variantes otimizadas
antigas, os 9 `.b64` antigos e o `manifest.json` antigo, e depois o ZIP. O `README-PARA-SONNET.md` do pacote pedia para
preservar os originais; segui a sua instrução mais recente e mantive a rastreabilidade por **hash** (abaixo) em vez
de arquivos. `PREVIEW.jpg`, `SHA256SUMS.json` e o README do ZIP não entraram no projeto (os hashes estão fixados no
teste V12).

### Hashes da arte retirada (fixados em `tests/Visual.Tests.ps1`, V12, para que não volte)

| Asset | SHA-256 do original antigo | SHA-256 da variante embutida antiga |
|---|---|---|
| logo | `17228418bc711e04…58033` | `dae917ec066c3cd2…bb0fb` |
| icon | `08588b99dd31dd17…2d349` | `65b604a0b41d76193…810ee` |
| banner | `b2f566ec6c715c43…ab269` | `55be2da96b8c6445…45950` |
| overview | `474b585dfd567df0…c0bf3` | `6a5f38eb42b50205…ddea` |
| findings | `61b6bffc37b992590…bebf4` | `3bca4f5d1a5199866…c6c1e` |
| hardware | `95f68548171f331049…0535a` | `6ac432c3d0bab7f490…f09b` |
| storage | `43ae816d34dd52e1…a682c` | `f3d88487983c0b5a…72521` |
| startup | `99b604c6653d2d82…fd4fc` | `43e7b1853f7ce0eef…b1a8` |
| privacy | `d2ee9512d461a63a…f374` | `3c429aefd135510e5…2932c` |

(Os hashes completos de 64 caracteres estão no teste.)

## 2. Arquivos modificados

| Arquivo | Mudança |
|---|---|
| `assets/branding/*-v2.png`, `assets/report/*-v2.png` | **novos** (9 fontes v2) |
| `assets/optimized/**` | regenerados (variantes, 9 `.b64`, `manifest.json` com `sourceSha256`) |
| `assets/brand-review.json` | **novo**: revisão de marca por asset e por hash de fonte |
| `tools/Optimize-Assets.ps1` | fontes `-v2`; registra `sourceSha256` no manifesto |
| `tools/Render-Samples.ps1` | +3 estados (`none-detected`, `critical`, `access-denied`) |
| `tests/fixtures/critical-disk.json` | **nova** fixture sintética (demo com um disco `Unhealthy`) |
| `src/reports/HtmlRenderer.ps1` | classe `risk-critical`/`risk-elevated` no cartão da nota; callout `bad` para a explicação crítica |
| `templates/style.css` | polimento (seção 7) |
| `tests/Visual.Tests.ps1` | lista de fontes v2, fixture crítica e nova suíte **V12** |
| `samples/*.html`, `samples/visual/*.html`, `samples/README.md` | regenerados / atualizados |
| `distribution-manifest.json` | FMP-10 movido para `resolved`; `assets/brand-review.json` em `development` |
| `docs/visual-integration.md`, `NOTICE.md`, `CHANGELOG.md` | atualizados para a v2 |

**Não alterados:** os seis coletores, regras, pontuação (`scoreAlgorithmVersion`, nota crítica limitada a 49),
scanner AST, consentimento, contratos de evidência, sanitização, `OutDir` padrão, `LICENSE`, locales (417 chaves).

## 3. Otimizações e tamanhos

| Chave | Fonte | Variante | Redução | Base64 (embutido) |
|---|---:|---:|---:|---:|
| banner (JPEG q88, opaco) | 1.561.671 B | 112.507 B | 7 % | 150.012 |
| logo | 790.921 B | 141.194 B | 18 % | 188.260 |
| icon | 1.622.090 B | 19.967 B | 1 % | 26.624 |
| overview | 1.407.918 B | 40.210 B | 3 % | 53.616 |
| findings | 1.329.623 B | 38.428 B | 3 % | 51.240 |
| hardware | 1.253.012 B | 38.660 B | 3 % | 51.548 |
| storage | 1.294.082 B | 37.548 B | 3 % | 50.064 |
| startup | 1.418.528 B | 39.312 B | 3 % | 52.416 |
| privacy | 1.358.962 B | 37.272 B | 3 % | 49.696 |
| **Total** | 12.036.807 B | **505.098 B** | 4 % | ≈ 673 KB |

Antes (arte antiga): 454.867 B. O banner foi convertido para JPEG (o PNG v2 fica preservado como fonte); a variante
JPEG tem 112 KB, abaixo do limite de 400 KiB por asset e dos 1,5 MiB somados. As fontes PNG v2 continuam com
transparência nas variantes RGBA. **HTML final: 0,713 a 0,739 MiB** (limite 8 MiB). Pacote `runtime` do manifesto:
**1,20 MB**.

## 4. Hashes novos (variantes embutidas, `manifest.json`)

| Chave | SHA-256 da variante embutida |
|---|---|
| banner | `21aeec991bc2b094d8b508d16372c55ecfd806b60b2b84405cfd6b65161b640a` |
| logo | `cebb9bfbc1f9401ad11fd9b0b487747aae5a547d9856ec276a276616c6a64d34` |
| icon | `3fd4e992c2955984b2427e5df79477f4dd910ccf4e4776ed36a5f757666b0d7a` |
| overview | `de391f6b202f40d37422cd8c32dc07e66c250e46d76c8b529f284a2bf9519712` |
| findings | `55d019c3259eba37fcff6b638ed4ce593b223442314e182a2b06a8f07f101afb` |
| hardware | `62d5cafdf9cbf8eab446b9d60c8d86dd4126f234c153c6b2acd214f3b88c6011` |
| storage | `554f7d50606bd443cfdc99a9ac31b86b42033cdb6168b3bc455f702dc94a6ef4` |
| startup | `905cbc75ff04ceca00e1924d66e07c9f50013e26bd7b211caf2e47a5d9658d4e` |
| privacy | `ae0df43cc1f1588f8a21cf67296b98fdc7229f1ede85c253a9b6863721069ebc` |

Hashes das nove **fontes** v2: os mesmos do `SHA256SUMS.json` do pacote, fixados no teste V12 e repetidos em
`manifest.json` (`sourceSha256`) e `assets/brand-review.json`.

## 5. Verificação do FMP-10 — **RESOLVIDO**

Inspeção feita olhando as imagens: (a) cada fonte v2 em tamanho cheio, (b) as variantes embutidas **decodificadas do
próprio Base64**, sobre fundo branco e azul-claro e em 46 px, (c) dentro do HTML renderizado, PT-BR e EN.

| Critério | Resultado |
|---|---|
| Logotipo oficial de quatro painéis do Windows | **ausente** nos 9 |
| Outras marcas de terceiros | **ausentes** |
| Escudos com check / checks verdes de aprovação | **ausentes** (nenhum verde de aprovação; verde só como acento no gradiente da marca) |
| Medidores de saúde fixos / ponteiro | **ausentes** |
| Identidade neutra e original | monitor genérico, lupa, gráficos e linha de pulso |
| Paleta coerente | navy / azul / ciano / teal nos nove, com o mesmo traço de contorno |

Observações honestas, nenhuma bloqueia:

- `privacy-v2` tem um **escudo com cadeado** (metáfora de privacidade, **sem check**). Mantido e registrado.
- `storage-v2` tem barras ascendentes decorativas no painel do disco (não ligadas a valor algum); `overview-v2` tem um
  anel/rosca decorativo sem ponteiro nem cor de veredito.
- O banner e o logo ainda trazem o texto "Windows Diagnostic & Audit Skill". É o nome do produto, referência de
  compatibilidade; segue para revisão jurídica (`NOTICE.md`). Aviso de não afiliação mantido (rodapé do laudo,
  rodapé de página, READMEs, `NOTICE.md`).
- A arte tem pequenas manchas de brilho na borda externa dos ícones grandes; a 46 px e a 96 px não são visíveis.

**Trava automática:** `assets/brand-review.json` guarda, por asset, o hash da fonte revisada e quatro campos
(`windowsLogo`, `thirdPartyMarks`, `approvalChecksOrShields`, `fixedHealthGauges`). O teste V12 exige um registro com
o hash **atual** e os quatro em `false`. **Verificado em vermelho→verde:** marcando `windowsLogo: true`, os nove
testes de FMP-10 falharam; um arquivo `fixmypc-logo.png` sem `-v2` reaparecendo também falhou. Os dois foram
revertidos e a suíte voltou a 290/290.

A arte é **decorativa**. O laudo continua tirando nota, cobertura, confiança e `riskLevel` só dos dados calculados
(nenhum desses valores foi tocado).

## 6. Comparação visual com a Etapa 7

Capturas "antes" do CSS: `docs/screenshots/stage71-before-*.png` (CSS da etapa 7, mas **já com a arte v2**, tiradas
depois da integração dos assets); a arte antiga aparece só nas capturas das etapas 4 e 7 (`stage7-*`, `desktop-*`,
`mobile-*`). "Depois": `stage71-after-*.png` e `stage71-final-*.png`.

| Ponto | Etapa 7 | Etapa 7.1 |
|---|---|---|
| Arte | Windows logo, escudos e medidores verdes | v2 neutra |
| Cartão da nota em risco crítico | idêntico ao de "sem risco" (navy + ciano) | borda superior e número em vermelho, barra vermelha |
| Explicação do risco crítico | callout âmbar | callout vermelho; nota limitada em âmbar |
| Resumo na 1ª tela (1440×1000) | só o título | nota, risco e cobertura visíveis |

## 7. Melhorias de design (CSS e um ajuste no renderizador)

- **Cabeçalho:** banner recortado a 260 px em telas largas (`object-fit: cover`) para o resumo subir; em celular,
  metadados em duas colunas (uma só a ≤ 360 px). O logo só repete na impressão (onde o banner some).
- **Resumo:** o cartão da nota ganha tinta por `riskLevel` (`risk-critical` vermelho, `risk-elevated` âmbar);
  `none_detected` fica neutro; nota provisória mantém listras âmbar e aviso. Cartão fixo (`sticky`) no desktop.
  Selo de risco virou retângulo arredondado (quebrava mal como pílula). Callout `bad` para a explicação crítica.
- **Achados:** a severidade continua no cabeçalho tingido com selo de texto e ícone (testei uma barra lateral colorida e
  **removi**: o hook de design a apontou como "side-tab" e era redundante); evidências em JSON quebram em espaços
  (antes partiam números no meio, ex.: `254663548 / 928`).
- **Hook de design (`impeccable`):** restam 2 apontamentos "side-tab" em `style.css` (cartão da nota, linhas 131 e 139).
  São uma faixa de 4 px **no topo** (sombra interna) que tinge o cartão por risco, não uma aba lateral. **Suprimidos com
  confirmação do usuário** (`side-tab=*` limitado a `templates/style.css`, gravado em `.impeccable/config.json`, pasta
  local fora do pacote). A supressão vale para qualquer "side-tab" futuro nesse arquivo.
- **Hierarquia:** títulos de achado `h3` sob `h2` (havia salto `h2→h4`).
- **Ícones de seção:** mantidos em 46 px / 12 mm na impressão (já discretos), sem competir com tabelas.
- **Impressão:** texto de abertura (`.lead`) não fica sozinho no fim da página; cartão da nota com tinta de risco
  também em papel; rodapé localizado e numeração.
- Sem novas fontes, gradientes, sombras ou animações.

## 8. Capturas de tela (`docs/screenshots/`, só desenvolvimento)

PT-BR e EN: `stage71-final-critical-pt-BR-320.png`, `…-375.png`, `stage71-final-none-detected-en-768.png`,
`stage71-final-provisional-pt-BR-1024.png`, `stage71-final-critical-en-1440.png`,
`stage71-final-access-denied-pt-BR-1440.png`; resumos: `stage71-after-critical-en-1440-summary.png`,
`stage71-ptBR-320-critical-summary.png`, `stage71-en-768-provisional-summary.png`; tabelas em celular:
`stage71-en-375-access-denied-advanced.png`; impressão: `stage71-print-a4-*-p1.png` / `p3.png`.
As capturas das etapas 4 e 7 continuam na pasta e **mostram a arte antiga**. `stage71-after-demo-ptBR-1440-findings.png`
foi tirada antes de remover a barra lateral dos achados (ver §7) e a mostra; as `stage71-final-*` e as amostras atuais não.

## 9. Estados diagnósticos (sete demonstrações sintéticas × PT-BR/EN)

Todas geradas por `tools/Render-Samples.ps1` (só lê `tests/fixtures`) e inspecionadas.

| # | Estado | Fixture | Resultado visto |
|---|---|---|---|
| 1 | Sem risco detectado | `win11-healthy` | 100/100, "Nenhum risco detectado nas verificações cobertas", sem tinta; texto "nem garante saúde perfeita" |
| 2 | Risco elevado | `demo-synthetic` | cartão âmbar, risco "Elevado", 79/100 |
| 3 | Risco crítico | `critical-disk` | 49/100, cartão e callout vermelhos, "Nota limitada a 49 (sem o limite, seria 65)" |
| 4 | Nota provisória | `limited-access` | 100 em âmbar com listras, "isto não prova que o computador está saudável", cobertura 86,7 % |
| 5 | Nota indisponível | `degenerate` | "–", sem medidor, texto "No gauge is shown" |
| 6 | Coletor com acesso negado | `advanced-mixed` | selos "Acesso negado" em âmbar, nota provisória |
| 7 | Falha / ausência de dados | `degenerate` e `limited-access` | módulos em erro/falha listados nas limitações; nada vira "OK" |

Observação: os estados 5 e 7 compartilham a fixture `degenerate`, que já mistura falha, erro e ausência de dados.

## 10. Responsividade

6 estados × 2 idiomas × 5 larguras (320, 375, 768, 1024, 1440) = **60 combinações**, no Chromium do Playwright,
servido por `127.0.0.1`: **0 rolagem horizontal, 0 imagens deformadas, 9/9 imagens carregadas em todas**.
(Heurística de "texto cortado" só acusou os `THEAD` ocultos de propósito nas tabelas empilhadas ≤ 640 px.)
Inspeção **visual** feita em 320, 375, 768, 1024 e 1440 px (subconjunto de estados, ver §8); as demais combinações
foram verificadas por métricas.

## 11. Impressão A4

PDFs gerados pelo Chromium (`printBackground: false`, como no padrão do navegador), **rasterizados com PyMuPDF** e
vistos página a página (críticos EN e PT-BR, demo PT-BR, sem risco PT-BR; 12, 12 e 8 páginas).

- **Rodapé localizado e numeração em 100 % das páginas:** 12/12, 12/12 e 8/8, texto extraído do PDF:
  "n / N · FIX MY PC · Ferramenta independente, sem afiliação à Microsoft" (PT-BR) e "… Independent tool, not
  affiliated with Microsoft" (EN).
- Quebras: achados, cartões e linhas de tabela inteiros; cabeçalhos de tabela repetidos; títulos não ficam órfãos
  (corrigi o texto de abertura que ficava separado dos achados).
- Barras de nota e de uso aparecem mesmo sem "gráficos de plano de fundo"; cartão crítico sai com borda e número
  vermelhos; selos "OK"/severidade legíveis em papel.
- Falta: um laudo muito longo termina com uma última página quase vazia (2 itens); aceitável.
- **Não verificado:** impressão por uma impressora/driver real nem a pré-visualização de outro navegador.

## 12. Acessibilidade

| Item | Resultado |
|---|---|
| Semântica | `header`, `nav` com rótulo, `main`, `footer`, link de pulo, `dl`, tabelas com cabeçalho |
| Títulos | `h1` único; `h2` por seção; `h3` nos achados (salto corrigido; teste novo proíbe `h4`) |
| Alt | banner e logo com texto de marca (não afirmam saúde); ícones de seção `alt=""` + `aria-hidden`; rodapé decorativo |
| Cor não é a única pista | risco, severidade, estado e nota sempre têm texto (e ícone nos selos); a tinta vermelha/âmbar é reforço |
| Contraste | razões WCAG **calculadas** para 25 pares de tokens usados: texto ≥ 4,89:1 (selo teal sobre teal-claro), números do cartão 9,07 e 11,31:1; barras ≥ 3:1. A única falha (barra lateral âmbar do achado, 2,45:1) deixou de existir ao remover a barra |
| `forced-colors` | bloco de etapa 7 mantido; verificado por **emulação** do Chromium |
| Zoom / celular | sem overflow a 320 px; não testei zoom de 200 % no navegador |
| Impressão | evidências completas preservadas; barras e selos mantidos |

**Não verificado:** leitor de tela real, tema de alto contraste do Windows real, contraste de pixels renderizados
(só dos tokens), zoom de 200–400 %.

## 13. CSP e XSS

- CSP no arquivo, **conferida nos bytes** de todos os 12 HTMLs (e por asserção exata em 4 renderizações no teste):
  `default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`.
- 0 `<script>`, 0 `on*=`, 0 `@import`, 0 `url(`, **0 URLs externas** fora dos `data:` de imagem; 9 `<img>` por laudo.
- Nenhum dado novo vira marcação: a classe `risk-*` só aceita `critical`/`elevated` (lista fechada); o texto do rodapé de
  impressão continua filtrado.
- As imagens embutidas passam pela mesma validação de etapa 4 (mime, assinatura, comprimento, limites); o fallback em texto
  continua coberto pelas suítes V9.
- **Ambiente:** o navegador desta máquina tem um antivírus (Kaspersky) que reescreve a meta CSP **no DOM** e injeta script
  (`gc.kis.v2.scr.kaspersky-labs.com`), gerando erros de CSP no console. Não é código do produto: o arquivo em disco está
  íntegro. Para a revisão, compare os **bytes** do HTML.
- O HTML não faz nenhuma consulta de rede (as únicas requisições vistas foram a da página local e as do antivírus,
  bloqueadas pela própria CSP).

## 14. Testes executados (offline, fixtures; execução final desta sessão)

| Comando | Etapa 7 | Agora |
|---|---:|---:|
| `fixmypc.ps1 -ValidateOnly` | 15 arquivos, 417 chaves | **PASS**: 15 arquivos, nenhuma violação, 417 chaves |
| `tests\Run.Tests.ps1` | 385/385 | **385/385** (inclui as suítes aninhadas) |
| `tests\Collector.Tests.ps1` | 85/85 | **85/85** |
| `tests\Visual.Tests.ps1` | 198/198 | **290/290** (+92, todos novos: V12 e fixtures) |
| `tools\Test-DistributionManifest.ps1` | PASS | **PASS** (runtime 1,20 MB; bloqueios restantes: licença e revisão jurídica) |

Nada foi enfraquecido: as únicas alterações em expectativas existentes foram a troca da lista de fontes originais
para os nomes `-v2` (V1) e a inclusão de `critical-disk.json` na varredura de todas as fixtures. Os 92 testes novos
cobrem: hashes das 9 fontes, arte retirada, arquivos sem `-v2`, `Optimize-Assets.ps1` e renderizador sem nomes
antigos, `sourceSha256`/`sourceBytes` do manifesto (embed defasado), Base64 do manifesto **dentro** do HTML PT-BR e EN,
CSP exata, URLs externas, limite de 8 MiB, tinta de risco (crítico/elevado/sem risco), `callout bad`, trava FMP-10 e
coerência com `distribution-manifest.json`.

Registro honesto: um teste meu falhou na primeira vez porque o HTML usa entidades (`sa&#250;de`); corrigi **o teste**
(aceita entidade ou caractere), não o laudo. E minha primeira mutação de verificação não alterou o JSON (espaçamento
do `ConvertTo-Json`) e passou "em branco"; refeita com expressão regular, falhou como esperado.

## 15. Pendências, limitações e recomendações

**Pendências (fora do escopo desta etapa, inalteradas):** licença MIT sem confirmação do proprietário;
revisão jurídica do nome "Windows" e do texto de não afiliação; P3-01, 02, 04 (as suítes ainda escrevem em `out\`),
05 a 13 e o filtro 22/45 do P3-15; `OutDir` padrão dentro da pasta da skill.

**Limitações:** o cartão da nota `sticky` no desktop não foi testado rolando a página (só por captura estática);
sem leitor de tela, alto contraste real do Windows, zoom ≥ 200 %, impressora real ou outros
navegadores; capturas visuais só em um subconjunto de estados e larguras; revisão de marca feita por inspeção visual
(IA), **não** por especialista; o repositório ainda não é git, então `.gitignore` e manifesto não foram exercitados
num commit.

**Riscos de publicação:** nome do produto com "Windows"; licença; a arte v2 foi gerada por IA (confirmar a titularidade
e a política de uso com o proprietário antes de publicar).

**Recomendações para a revisão independente:**
1. Olhar você mesmo os nove PNG v2 e `assets/brand-review.json` (não confie só na minha revisão).
2. Rodar as quatro suítes e o verificador do manifesto num clone limpo.
3. Conferir a CSP pelos bytes do arquivo, em navegador sem antivírus que injete scripts.
4. Imprimir/salvar em PDF um laudo PT-BR e um EN e olhar a numeração, o rodapé e as barras.
5. Testar com tema de alto contraste e leitor de tela reais.
6. Decidir licença, nome do produto e titularidade da arte antes de qualquer release.
