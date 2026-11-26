# Artwork provenance / Proveniência das artes

**English** below · [Resumo em português](#resumo-em-português)

This file records the origin and rights status of the nine v2 images of FIX MY
PC and of every copy derived from them. It keeps three kinds of statement apart:
**technical evidence** read from the files, the **owner's declaration**, and
**terms and law** that apply to them. It is **not** a legal opinion. No lawyer
has reviewed it, and it grants no license.

Last updated: 2026-11-26, branch `release/fixmypc-2.0-prep`.

## 1. Technical evidence (read from the files)

**Content Credentials (C2PA).** Each of the nine images as delivered has a
`caBX` chunk holding a C2PA manifest. Parsed as data, every manifest states:

- generator `ChatGPT`, version `gpt-image`, signed as "OpenAI Media Service API"
  (OpenAI OpCo, LLC), with time stamps from the "OpenAI TSA" certificate chain;
- `digitalSourceType` = `http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia`
  (IPTC term for AI-generated media);
- actions `c2pa.created` and `c2pa.converted`, plus `c2pa.watermarked.unbound`
  (the generator reports an invisible watermark);
- **no ingredient**: no input image is declared. An empty ingredient list does
  not prove that no reference was used. That point rests on the owner's
  declaration (section 2), not on the metadata.

The signatures were **not** cryptographically validated: no C2PA validator is
installed in this environment.

**Time.** The manifest time stamps fall between 2026-11-21 01:22 and 01:24 UTC,
which is the evening of 2026-11-20 in Brasília time (UTC-3).

**Project history.** The images arrived in a package named
`FIX-MY-PC-v2-assets.zip` at stage 7.1 (2026-11-20). Their hashes matched that
package, which was deleted after integration
(`docs/reviews/SONNET-5.5-STAGE7.1-VISUAL-FINAL.md`). They replaced the v1
artwork, which showed the Windows logo. The v1 files were deleted before the Git
repository existed, and no commit contains them.

**Third-party marks.** The visual review in `assets/brand-review.json` (FMP-10)
and a new look on 2026-11-26 found no Microsoft logo, no other third-party logo
or brand mark, no approval check and no gauge. Only generic symbols appear
(magnifier, monitor, padlock, share arrows, the power symbol). That review was
done by AI models, not by a trademark specialist.

## 2. Owner's declaration (2026-11-26)

The project owner, Lucas Sehenth, declared in writing to the assistant that:

1. the nine v2 images were requested from ChatGPT during the development of FIX
   MY PC, on 20 and 21 November 2026, from his **personal** ChatGPT account, not
   a business or enterprise account;
2. no third-party images were used as references or inputs;
3. the images were created specifically for FIX MY PC;
4. the v2 package was assembled by ChatGPT itself;
5. the holder named for the project is Lucas Sehenth;
6. the code license stays MIT.

These are the owner's statements. The repository cannot verify them
independently. They are consistent with the C2PA evidence: generator,
dates, and no declared ingredient.

## 3. Banner and logo: subtitle replaced (2026-11-26)

The first v2 banner and logo had the text "Windows Diagnostic & Audit Skill"
drawn into the image. Microsoft's trademark guidelines
(<https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general>)
say third parties should not put Microsoft brand assets in a product name or
tagline. At the owner's request, that line was replaced with
**"PC Diagnostic & Audit Skill"**. Nothing else in the two images changed.

How it was done (Claude Opus 5.5 in Claude Code, System.Drawing, no generative
model):

- The old line's ink box was measured on the C2PA-signed originals: logo x
  778-2095, y 475-556; banner x 696-1475, y 367-411. It was erased with a 4 px
  margin. In the logo, the background was set back to transparent, as it was.
  In the banner, each pixel column was interpolated from the 5 rows above and
  below the box.
- The new line was set in **Montserrat** (SIL Open Font License 1.1), the
  typeface the original lettering matches: SemiBold in the logo, Medium in the
  banner. It uses the same size, colour (`#27394B` logo, `#C6DBEB` banner),
  left edge and top, and its letter spacing is widened so the line spans the
  gradient bar, as the original did. The font files are not distributed. The
  OFL allows images made with the font.
- A check of the 5-12 px band around the box found no remaining ink from the old
  text. The only pixels there have alpha 1, and the original had the same ones.
- The edited files no longer carry C2PA metadata, because re-encoding drops it.
  The originals they derive from are recorded below by hash.

| Image | First v2 source (C2PA-signed, retired) | Current source |
|---|---|---|
| logo | `ce2ba790104d18a58e55996e49ce902fbee5cad26549439c742e9b435819b351` | `659e9d276783c6396148b7b39bc9edc56574abefc5c11bbabd368869533bf434` |
| banner | `70b2b0a1dce3d7d7eefc454861c2d8bb68078a3edf46c9389a4ff67107a27663` | `45c0010109da7b750d78c0e533f7f0807bb90ea40741e37e796d5942e8385608` |

The retired sources and their embedded variants are listed in
`tests/Visual.Tests.ps1` (V12) so they cannot come back. The other seven images
were not touched, and their optimized and Base64 copies were regenerated
byte-identical.

## 4. Derivation chain

`tools/Optimize-Assets.ps1` resizes each source with System.Drawing and writes
a PNG or JPEG under `assets/optimized/`. The renderer reads only the Base64 file
of that variant. On 2026-11-26, the source, optimized and decoded-Base64 hashes
of all nine keys matched `assets/optimized/manifest.json`. Re-encoding drops
C2PA, so the embedded copies carry no Content Credentials.

| Key | Source | Size | Current source SHA-256 | C2PA manifest of the generated image | Optimized variant | Embedded |
|---|---|---|---|---|---|---|
| `banner` | `assets/report/fixmypc-report-banner-v2.png` | 2172x724 | `45c0010109da7b75…` (edited, see §3) | `urn:c2pa:e2e7eeed-cd34-4a29-aa9b-fb8aaeea6a33` (on the retired original) | 1440x480 JPEG `a224df95ad9fce04…` | `embed/banner.b64` |
| `logo` | `assets/branding/fixmypc-logo-v2.png` | 2172x724 | `659e9d276783c639…` (edited, see §3) | `urn:c2pa:18d79fed-1d48-4c5e-8664-4864b30293ee` (on the retired original) | 720x240 PNG `e2111d9ebcc091b0…` | `embed/logo.b64` |
| `icon` | `assets/branding/fixmypc-icon-v2.png` | 1254x1254 | `edd82d4738abb496b196add3b52d947ebeec99a2e9888c24b61727b558c23c72` | `urn:c2pa:fa670eb6-d542-4c3e-9717-f1ec91b56f81` | 96x96 `3fd4e992c2955984…` | `embed/icon.b64` |
| `overview` | `assets/report/fixmypc-overview-v2.png` | 1254x1254 | `021f74bc0c30288a0344c914b47e53190b9700483b055d6d75d7846fd1274021` | `urn:c2pa:5b1a7065-1a2e-44c4-8c08-782cd0ae028c` | 144x144 `de391f6b202f40d3…` | `embed/overview.b64` |
| `findings` | `assets/report/fixmypc-findings-v2.png` | 1254x1254 | `c70099d1fc632ae03a4351e5d4b9d3538bf61f43d807e114a1f88e80a5b64ab4` | `urn:c2pa:8b598a5d-d843-4bbf-98f9-f0fde58a881f` | 144x144 `55d019c3259eba37…` | `embed/findings.b64` |
| `hardware` | `assets/report/fixmypc-hardware-v2.png` | 1254x1254 | `bc8a36d59d354b64ff23843b6fd69e7e94856d7f0ce5a5cbcbff244300ce2121` | `urn:c2pa:21fe98be-b388-4e67-aa4d-2d8a9371433f` | 144x144 `62d5cafdf9cbf8ea…` | `embed/hardware.b64` |
| `storage` | `assets/report/fixmypc-storage-v2.png` | 1254x1254 | `c0565aeb5fe18d7f6484ca81d0f12f126e83b6d3dcf3b210dadd723c7176917c` | `urn:c2pa:4ad0bb4f-c644-4266-99c4-d07d66e8823b` | 144x144 `554f7d50606bd443…` | `embed/storage.b64` |
| `startup` | `assets/report/fixmypc-startup-v2.png` | 1254x1254 | `5d59a4616a94439e4564cb0c207e50b6e0778646ebcd71df5f926a9017dbce74` | `urn:c2pa:30cca0ee-bb7f-4313-b908-b897d1cb5829` | 144x144 `905cbc75ff04ceca…` | `embed/startup.b64` |
| `privacy` | `assets/report/fixmypc-privacy-v2.png` | 1254x1254 | `bfabf3651d6daddec242733717eeab004fa5ab0597a18954bc76aba404acc523` | `urn:c2pa:b704c1b7-e4ca-494c-b6e4-59c4a2342b6d` | 144x144 `ae0df43cc1f1588f…` | `embed/privacy.b64` |

Full hashes of the optimized variants are in `assets/optimized/manifest.json`.

Copies that carry the artwork:

| Copy | Where | In Git | Updated 2026-11-26 |
|---|---|---|---|
| Base64 payloads (runtime) | `assets/optimized/embed/*.b64` | yes | banner, logo |
| Every generated `report.html` | user output folder | no | from the next run on |
| 12 sample reports | `samples/demo-report*.html`, `samples/visual/*.html` | yes | banner, logo and subtitle text replaced in place; the rest of each file is unchanged |
| 3 README screenshots | `docs/screenshots/readme-*.png` | yes | new captures |
| 30 stage-10 / stage-7.1 screenshots | `docs/screenshots/stage10-*`, `stage71-*` | yes | **not changed**: historical review evidence; most show the old subtitle |
| Earlier commits | Git history (`8f8664a`, `6efcaf8`, `a70447f`) | yes | **not changed**: hold the first v2 banner and logo |

## 5. Terms and law (not legal advice)

**OpenAI terms.** OpenAI's Terms of Use (effective 2026-01-01,
<https://openai.com/policies/terms-of-use/>) apply to a personal ChatGPT
account. As read on 2026-11-26:

- As between the user and OpenAI, the user owns the output, and OpenAI assigns
  to the user its rights in the output, *if any*.
- The terms do not bar commercial use or redistribution of image output. Use
  must follow the law and OpenAI's usage policies, and must not infringe
  others' rights.
- Output may not be unique: other users can receive similar output, and the
  assignment does not cover their output.
- Output must not be presented as human-made. `NOTICE.md`, the READMEs and this
  file state that the artwork is AI-generated.

**Copyright may not exist.** Images generated by AI without enough human creative
contribution may have no copyright protection in some countries. In Brazil,
Law 9.610/1998 defines the author as a natural person. The US Copyright Office
does not register AI-generated material that lacks human authorship. In that
case nobody holds exclusive rights, the owner included, and third parties
could reuse the images. The subtitle edit in §3 is set type, which adds little
authorship. No professional has assessed this for these files.

## 6. Rights status

| Image | Status | Basis | Limits |
|---|---|---|---|
**Owner's decision (2026-11-26).** The owner authorized releasing the nine v2
images under the **MIT License**, with the notice `Copyright (c) 2026 Lucas
Sehenth`, **to the extent of the rights he holds**. The AI-generation credit and
this C2PA record stay with the artwork.

| Image | Status | Basis | Limits |
|---|---|---|---|
| icon, overview, findings, hardware, storage, startup, privacy | **MIT, to the extent of the holder's rights** | C2PA evidence + owner's declaration and authorization + OpenAI terms + no third-party marks | §5: no exclusive rights claimed; signatures not validated; not legal advice |
| banner, logo | **MIT, to the extent of the holder's rights** (subtitle fixed, §3); visually approved by the owner on 2026-11-26 | same, plus the documented edit | same as above |

The same applies to every derived copy listed in §4.

What the MIT grant does **not** do:

- It does not create exclusive rights. If no copyright subsists in an image, the
  grant passes on nothing, and the image may already be free for anyone to use.
- It grants no trademark rights. The FIX MY PC name, and the name and logo used
  as a brand, are not licensed by MIT. The owner keeps the name (section 7).

## 7. Preliminary name search (2026-11-26)

Searched by the assistant in public databases. This is a screening, not a
clearance search. Holders who are private individuals are not named here.

**INPI (Brazil)**, pePI, basic trademark search, "radical" mode, data updated to
2026-11-24:

| Query | Result |
|---|---|
| FIX MY PC | no result |
| FIXMYPC | no result |
| FIX PC | no result |
| FIX MY | 4: "FIX MY TECH - FXMYTC" 929747100 (NCL 09) and 929747321 (NCL 37), both *pedido definitivamente arquivado*; "FixMyCell" 937117005 (NCL 09) and 937118176 (NCL 35), *registro de marca em vigor* (individual holder) |

**WIPO Global Brand Database** (covers many national and regional offices),
brand name, exact strategy:

| Query | Mark | Office / number | Nice | Status |
|---|---|---|---|---|
| fix my pc | FIX MY PC | US 78597778 | 35 | ended 2006 |
| | FIX MY PC | UK UK00003327746 | 37 | ended 2018 |
| | COME FIX MY PC | AU 1710189 | 37 | ended |
| | FIX MY PC STORE | US 85818576 | 37 | ended 2024 |
| | **FIX MY PC STORE** | **US 8110109** (A & B Alliance, Inc.) | **37** | **registered, 2026-01-20** |
| | 800-FIX-MY-PC | US 75304606 | 42 | ended 2001 |
| | 1800 FIX MY PC | AU 1181643 | 9, 37, 42 | ended |
| fixmypc | FIXMYPC | AU 838607 | 37 | ended |
| | FIXMYPC.COM | US 75611802 | 37 | ended 2003 |

A broader WIPO "contains" query also listed **"MY PC", BR 937076740, NCL 9,
pending (2024-11-20)**, with an individual holder.

Reading the results (not a legal conclusion):

- FIX MY PC falls mainly in NCL 9 (downloadable software) and possibly NCL 42
  (IT services). No live identical mark was found in Brazil.
- In the United States, "FIX MY PC STORE" is registered in NCL 37 (computer
  repair services). That is a different class from software, but the names
  share the "FIX MY PC" core, so a conflict cannot be ruled out there.
- In Brazil, "MY PC" is pending in NCL 9, and "FixMyCell" is registered in
  NCL 9 and 35.
- Not searched: the USPTO and EUIPO interfaces directly, unregistered use,
  company names, domain names, app stores and GitHub names. Finding no exact
  match does not mean there is no conflict.

**Owner's decision on the name (2026-11-26):** keep FIX MY PC. The similar US
registration above stays on record. Seek a legal assessment if a relevant doubt
comes up.

## 8. Open items and history

1. **Visual approval of the edited banner and logo:** given by the owner on
   2026-11-26, which closed `LEGAL-REVIEW`.
2. **Git history (owner decision, 2026-11-26).** The public `main` is not
   rewritten and no force-push is used. The local commits are integrated into a
   single consolidated commit on top of `origin/main`, so the intermediate
   commits are not published. Two limits remain:
   - the public commit `8f8664a` already contains the first v2 banner and logo,
     with "Windows Diagnostic & Audit Skill";
   - the 30 historical stage-10 and stage-7.1 screenshots in `docs/screenshots/`
     are kept as review evidence, and most of them show that subtitle.
3. Optional: validate the C2PA signatures of the seven unedited images with a
   Content Credentials verifier.
4. No professional legal review has taken place.

## Resumo em português

- **Evidência técnica:** as nove imagens trazem manifesto C2PA que declara
  geração pelo ChatGPT (`gpt-image`, OpenAI), tipo `trainedAlgorithmicMedia`,
  em 20/11/2026 à noite (horário de Brasília), sem imagem de entrada declarada.
  A ausência de ingredientes declarados não prova, por si só, a ausência de
  referências. As assinaturas não foram validadas.
- **Declaração do proprietário (26/11/2026):** conta pessoal do ChatGPT, sem
  imagens de terceiros como entrada, criadas para o FIX MY PC, pacote montado
  pelo próprio ChatGPT, titular Lucas Sehenth, código sob MIT.
- **Banner e logotipo:** o subtítulo "Windows Diagnostic & Audit Skill" foi
  substituído por "PC Diagnostic & Audit Skill", com a mesma fonte (Montserrat,
  OFL), cor, posição e alinhamento. Nada mais mudou. Os hashes antigos ficaram
  registrados e bloqueados no teste V12.
- **Situação:** por decisão do proprietário (26/11/2026), as nove artes v2 e
  suas cópias derivadas estão sob a **Licença MIT, na extensão dos direitos que
  ele detém**. Pode não existir direito autoral sobre imagem gerada por IA (a
  Lei 9.610/1998 define autor como pessoa física), então nenhum direito
  exclusivo é reivindicado. O crédito de geração por IA e o registro C2PA
  acompanham a arte. A MIT não concede direitos de marca.
- **Nome:** o proprietário mantém FIX MY PC. Na busca preliminar, o INPI não
  retornou nada para "FIX MY PC", "FIXMYPC" ou "FIX PC". Nos EUA existe o
  registro em vigor **"FIX MY PC STORE" (US 8110109, classe 37)**, e no Brasil
  "MY PC" está pendente na classe 9. Se surgir dúvida relevante, buscar
  avaliação jurídica. Isso não é parecer jurídico.
- **Histórico:** a `main` pública não é reescrita. As alterações locais entram
  em um único commit consolidado. O commit público `8f8664a` e as 30 capturas
  históricas ainda mostram o subtítulo antigo.
- **Aprovação visual:** o proprietário aprovou o banner e o logotipo editados em
  26/11/2026, o que encerrou o `LEGAL-REVIEW`.
