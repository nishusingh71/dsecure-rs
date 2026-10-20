# DSecure Rust backend: Report PDF templates (draft v1, 20 Oct 2026)

Owner: Mr. W. Author: architect. Status: **DRAFT**. Decision **D-19 CLOSED**: owner (20 Oct 2026) *"Reports Pdf h ushmein nahi chaiye waise banenga jaise dotnet report hoti h"* → **no PAdES / Adobe signature**; report PDFs **look like today's .NET reports** (same sections, labels, order, branding from `pdf_export_settings`); hybrid: server signs the data, clients render; QR/verify footer added.

**Evidence (read-only, .NET repo, working tree 20 Oct 2026; line numbers move):** `Services/PdfService.cs` (`SetupCleanPageLayout` :58, `CompactTableBlock` :146, `AddSignaturesBlock` :179, `GenerateReport` :246, `GenerateDriveEraserReport` :437, `GenerateDiagnosticReport` :685, `GenerateSystemCleanerReport` :910), `Helpers/DiagnosticReportMapper.cs`, `Controllers/DriveEraserReportsController.cs` `MapToReportData` (:1299), `Reports/Documents/AutopilotReportDocument.cs`, `AutopilotConsolidationDocument.cs`, `Reports/Branding/DSecureTheme.cs`, `Reports/Models/AutopilotReportModel.cs`, `Models/PdfExportSettings.cs`, `Autopilot/Services/AutopilotV2Service.cs` (branding save :1494), and contracts `docs/contracts/{drive-eraser §9, diagnostic §1.4 §2, file-eraser-and-public-reports §5 §10, dssc-freeze-privatecloud A.7-A.8, autopilot §9-§10}.md`. No PDF was rendered for this doc (layout values read from code; **visual output not verified**).

Saath: `ARCHITECTURE.md` §10 (pipeline), `DATABASE.md` §6 (`reports`, `report_branding_versions`), `SECURITY.md` §7.

---

## 1. Pipeline and responsibilities

| Step | Who | What |
|---|---|---|
| 1 | Server (upload) | Report JSON → product **mapper** (Rust port of the .NET mapper; rules §4-§8) → `render_data` (final strings exactly as printed, defaults applied, tables as rows) |
| 2 | Server | Personnel text snapshot (branding text slots resolved, §2.3) + `branding_version_id` + `render_sha256 = SHA-256(JCS(render_data))` into `certificate_payload` → Ed25519 signature (`ARCHITECTURE.md` §10.1) |
| 3 | Server | `GET /api/v1/reports/{p}/{public_id}/certificate` returns `template_id`, `render_data`, signature fields, `verify_url`, `fingerprint`, branding (text + signed image URLs) |
| 4 | Client (dashboard, desktop app, verify page) | **Layout only**: draws `render_data` with the template of `template_id` (this doc). Client never re-maps raw report JSON (one mapping implementation = server) |
| 5 | Anyone | QR / verify URL → server re-verifies signature → shows server data + fingerprint |

Rules:
- `template_id` versioned (`drive.v1`, `diagnostic.v1`, `file.v1`, `cleaner.v1`, `autopilot.v1`, `autopilot_consolidation.v1`). Layout change = new version; old reports keep their version.
- Not pixel-identical with QuestPDF (different engines), but: same page size, margins, fonts (metric-compatible), sections, labels (exact text and case), order, colours, image slots, tables, footer. Acceptance = text-extraction equality with golden fixtures + visual diff threshold (§11).
- Missing data: print the .NET default for that field (tables below). .NET sometimes printed an empty cell because its mapper returned `""` instead of null; v1 prints `N/A` there (deviation DV-3, §12).

---

## 2. Branding slots (legacy `pdf_export_settings` → `report_branding_versions`)

### 2.1 Slots
| Slot (v1) | Legacy column | Used by | Notes |
|---|---|---|---|
| `report_title` | `report_title` | (stored; .NET templates never print it, §4-§7) | Keep for parity of settings UI |
| `header_text` | `header_text` | Drive (page title), Diagnostic (page title) | Default per product (§4, §5) |
| `technician_name`, `technician_dept`, `technician_company` | same | Personnel blocks, signature captions | name encrypted at rest |
| `validator_name`, `validator_dept`, `validator_company` | same | same | — |
| `left_logo` | `header_left_logo` | Header left, footer left (clean layout), Autopilot header + consolidation footer | image |
| `right_logo` | `header_right_logo` | Header right | image; background removed (§2.4) |
| `watermark` | `watermark_image` | Page background | image; opacity rule per product |
| `technician_signature`, `validator_signature` | same | Signature row | image |
| *(not PDF)* `column_view_config` | `column_view_config` | Autopilot device table UI | → `member_preferences` (`autopilot.device_table.columns`), never deleted by branding reset (contract file §5.4 bug) |

### 2.2 Product keys and resolution
- Product keys: `global`, `drive` (legacy `DriveEraser`), `diagnostic` (`Diagnostic`), `file` (`FileEraser`), `cleaner` (`DSSC`), `autopilot` (`Autopilot`).
- Resolution (same as .NET): product row, else `global` row, else built-in defaults. Per slot, not per row: an empty text slot falls through to the default of §4-§8 (.NET: "settings if non-empty else JSON else default").
- Owner of branding = **tenant** (v1), managed by `reports.branding.manage` (owner/admin). .NET keyed it by account email (case-sensitive lookups = bug); migration maps the tenant owner's rows; subuser-owned rows (if any) → report to owner, not imported automatically (not verified how many exist).

### 2.3 Issue-time snapshot (D-62)
- At signing, the server stores `branding_version_id` and puts the **resolved personnel text** (names, depts, companies exactly as printed) into the signed payload. Images are referenced by `branding_version_id` (immutable version rows) → re-render years later gives the same PDF.
- Option `?branding=current` re-renders with the current version (".NET behaviour"); the verify page always shows the issue-time version.

### 2.4 Image rules
- Accepted: PNG, JPEG, GIF, BMP by magic bytes (same check as .NET `IsValidImage`); max 2 MB each (D-59); stored encrypted in object storage; legacy values (`data:` prefix, `GZIP:`+base64, project-compressed base64 via `ImageCompressionHelper`) decoded once by the importer (decoder port; format not inspected here: **not verified**).
- Pre-processing at branding save (worker job, bounded): right logo → near-white pixels transparent (tolerance 40, .NET `RemoveBackground`); Drive custom watermark → background removal + 15% opacity; Autopilot watermark → opacity applied (.NET `ApplyOpacity`; contract says 0.22, value not re-verified). Processed variant stored as its own blob, so clients only draw.
- An invalid/missing image = slot absent → built-in default asset (§10) where .NET used one, else empty area.

---

## 3. Common "clean layout" (Drive, Diagnostic, File, Cleaner) — from `SetupCleanPageLayout`

| Element | Spec |
|---|---|
| Page | US Letter (612 × 792 pt), margin 40 pt all sides |
| Default text | Liberation Sans 10 pt, black (.NET uses Liberation Sans; bundle the OFL font) |
| Watermark | If valid image: centred behind content, box 300 × 300 pt, fit area |
| Header | Table 3 columns relative 2.2 : 3.6 : 2.2. Left: logo max height 30 pt, max width 100 pt, aligned left/middle (no logo = empty 30 pt cell). Centre: title text 14 pt bold, centred. Right: logo (background-removed variant) max height 45, max width 120, right/middle |
| Content | Top padding 20 pt, bottom 10 pt, single column |
| **Block** (`CompactTableBlock`) | Title 10 pt bold black; 1 pt black rule (3 pt below title); 4-column table relative 1.5 : 2.5 : 1.5 : 2.5; label cells 9 pt **bold**, value cells 9 pt; vertical padding 1 pt; items flow two per row (odd last item → two empty cells); 5 pt bottom padding |
| Section heading (non-block) | 11 pt bold + 1 pt rule (e.g. "AUDIT PROOF", "TARGET VOLUME DETAILS") |
| Certification statement | 1 pt rule, centred text (9 pt; Drive 8 pt), 1 pt rule |
| **Signature row** (`AddSignaturesBlock`) | Row, top padding 15: [QR column rel 2.2: QR 80 × 80 pt centred, caption **"SCAN TO VERIFY"** 7 pt bold] · 15 pt gap · [Technician rel 3.5: signature image max h50 w120 centred, or text "N/A" 10 pt in a 60 pt box; 1 pt rule; caption "`<ROLE>` SIGNATURE" 7 pt bold; name 7 pt; company 7 pt] · 15 pt gap · [Validator rel 3.5: same, caption "VALIDATOR SIGNATURE"] |
| Signature captions | `<ROLE>` = `TECHNICIAN` (Drive, File, Cleaner) or `DIAGNOSTIC TECH` (Diagnostic); validator always `VALIDATOR` |
| Footer | Top padding 10. (1) footer sentence italic 7 pt, grey (QuestPDF `Grey.Darken2` = #616161), centred. (2) 1.5 pt black rule. (3) Row: left rel 1.2 = left logo height 18 pt, or text "D-Secure" 8 pt bold; centre rel 4 = "**Verification Code:** `<code>`" 5.5 pt bold; right rel 1 = "Page `<n>`" 10 pt |
| Status colours | Green `#4CAF50` (QuestPDF Green.Medium), red `#F44336` (Red.Medium), else black. Rule `status_color`: lower-cased text contains `successful`/`completed`/`passed` or equals `pass`/`success`/`complete` → green; contains `failed` or equals `fail` → red |
| Long paths | `SafePath`: > 180 chars → first 177 + `...` |

**v1 verification additions (all products, D-60):**
- QR content: `https://<verify-host>/v/{public_id}#{fingerprint}` (replaces `{QrReport:BaseUrl}/{id}`; legacy hosts `qrcloud.dsecuretech.com/{id}` and `autopilotdetection.dsecuretech.com/report/{id}` keep redirecting for old PDFs). QR error correction M, D-Secure logo (`DSecureLogo.png`) centred ≤ 20% area (as .NET).
- `<code>` in the footer and in "AUDIT PROOF / Verification Code" = `DSV1 <fingerprint as 4×4 hex groups> · key <kid>`; AUDIT PROOF line additionally prints the Ed25519 signature (base64url, 86 chars) at 7 pt grey. (.NET printed an RSA base64 string here; same position and style.)
- Added footer line under the row (6 pt, grey, centred): `Verify at <verify-host>/v/{public_id} · Report ID {public_id}`. This is the only new visual element.

---

## 4. Drive Eraser — `drive.v1` (from `GenerateDriveEraserReport` + `MapToReportData`)

**Page 1** (title = `header_text`, default **"D-Secure Drive Eraser Report"**; footer sentence: "The information contained in this report is digitally protected and generated by the D-Secure data erasure process.")
| # | Block | Label → `render_data` field ← source (default) |
|---|---|---|
| 1 | REPORT INFORMATION | `Report ID:` ← JSON `report_id`, else `uuid`, else public id · `Report Date:` ← JSON `report_date`, else report timestamp (§9 date format) · `Software Version:` ← JSON `software_version` (default "D-Secure Drive Eraser 1.0.0") |
| 1a | Verification line (not a block) | 2-col table 1.5 : 6.5: "Verification Code:" 8 pt bold + `<code>` 6.5 pt grey |
| 2 | PERSONNEL & AUTHORITY | `Performed by:` ← branding technician_name, else JSON `technician_name`, else "System Technician" · `Validated by:` ← validator_name / JSON `validator_name` / "System Validator" · `Technician Org:` ← technician_company / JSON `organization_1` / customer name / "N/A" · `Validator Org:` ← validator_company / JSON `organization_2` / customer name / "N/A" |
| 3 | CUSTOMER DETAILS | `Customer Name:` ← JSON `customer_name` ("Customer") · `Customer Address:` ← JSON `customer_address` ("---") |
| 4 | ASSET INFORMATION | `Computer:` ← `model_name` · `System Serial:` ← `system_serial` · `Manufacturer:` ← `manufacturer` · `MAC Address:` ← first non-empty `network_adapters[].mac_address`, else root `mac_address` (all "N/A") |
| 5 | ERASURE STATISTICS SUMMARY | `Total Disks:` ← `total_disks` (int, 0) · `Successful Disks:` ← `successful_disks` · `Disks to Erase:` ← `total_disks` · `Failed Disks:` ← `failed_disks` |
| 6 | ERASURE EXECUTION DETAILS | `Erasure Method:` ← stored method (server row), else JSON `erasure_method` · `Status:` ← server result status, else JSON `status` · `Total Volumes:` ← `total_disks` · `Verification:` ← `verification_type` ("none") · `Start Time:` ← `start_time` · `End Time:` ← `end_time` · `Duration:` ← `duration` · `Write Passes:` ← `write_passes` ("N/A") |
| 7 | ASSET DETAILS | `Machine Asset Tag:` ← `asset_tag` ("N/A"); then per `disk_asset_tags[]` with both values: `Drive {drive_id} Asset Tag:` ← `asset_tag` (empty values → "—") |
| 8 | Statement (8 pt) | "I hereby certify that the data erasure process detailed above has been executed in accordance with defined standards, ensuring that all unnecessary data has been permanently and irreversibly erased." |
| 9 | Signature row | `TECHNICIAN` / `VALIDATOR`; names + companies as block 2; signature images: JSON `technician_signature` / `validator_signature` (base64 PNG) override branding, else branding, else default `signsample.png` |

**Page 2+ "Annexure: System & Erasure Details"** (11 pt bold + rule)
| # | Section | Content |
|---|---|---|
| 10 | HARDWARE TEST RESULTS (only if `hardware_tests[]`) | 10 pt bold title + rule; 4-col paired grid: `{component}:` bold 9 pt / `{status}` 9 pt bold coloured by `status_color` |
| 11 | HARDWARE INFORMATION (block) | `Manufacturer:` · `Chassis Type:` ← `chassis_type` · `Model Name:` ← `model_name` · `UUID:` ← `uuid` · `System Serial:` · `SKU Number:` ← `sku_number` ("---") · `Chassis Serial:` ← `chassis_serial` · `USB Hub:` ← `usb_hub` ("---") · `Board Serial:` ← `board_serial` · `Memory (RAM):` ← `memory_ram`, else `memory_banks[]` joined (" \| ") · `Media Source:` ← `media_source` · `Asset Tag:` ← `asset_tag` ("---") · `Media Destination:` ← `media_destination` · `Processor:` ← `"{processor.name} @ {processor.current_speed}, Cores: {processor.cores}"` · `Graphics Card:` ← `graphics_card` · `USB Controller:` ← `usb_controller` · `BIOS:` ← `"Vendor: {bios_vendor}, Version: {bios_version}, Release: {bios_release_date}, SMBIOS: {bios_smbios_version}"` (all others "N/A") |
| 12 | TARGET VOLUME DETAILS | 11 pt bold + rule; per `erasure_results[]` (then `erasure_log[]` rows as fallback, file-eraser style): heading = target label upper-case 9 pt bold (`model`, else `path`/`file`, else "Unknown Disk"); 4-col grid: `Capacity:` ← `size` · `Total Sectors:` ← `total_sectors` · `Erased Sectors:` ← `processed_sectors` · `Status:` ← `status` (coloured, bold) · `Duration:` ← report `duration`. None → italic 9 pt "No volume details available." |
| 13 | CUSTOM FIELDS (only pairs with both non-empty) | block of `{name}:` / `{value}` from `custom_fields[]` |
| 14 | "S.M.A.R.T Health Data" (only if `smart_health` non-null; new page) | 11 pt bold + rule; indented JSON dump, monospace 8 pt (.NET Courier New → Liberation Mono) |
Not printed (parity): `disks[]`, `pre_wipe_partitions[]`, `sound_cards[]`, `optical_drive`, `bios_features` (parsed by .NET but absent from the Drive template). JSON value → text: strings as-is, numbers/bools as JSON text, null → empty, objects/arrays → compact JSON text (.NET `JsonElement.ToString()`).

---

## 5. Diagnostic — `diagnostic.v1` (from `GenerateDiagnosticReport` + `DiagnosticReportMapper`)

Title = `header_text`, default **"D-Secure Diagnostic Report"**. Footer sentence: "The information contained in this report is digitally protected and generated by the D-Secure system diagnostic process." No AUDIT PROOF block in .NET; v1 verification code appears in the footer (and QR) only — same as .NET.

**Page 1**
| # | Block | Labels ← source (default) |
|---|---|---|
| 1 | PERSONNEL & AUTHORITY | `Technician Name:` ← technician_name / JSON `technician_name` / "System Technician" · `Validator Name:` ← validator_name / JSON `validator_name` / "System Validator" · `Department:` ← technician_dept ("IT Dept") · `Department:` ← validator_dept ("Audit Dept") · `Organization:` ← technician_company / JSON `organization_1` / customer name / "N/A" · `Organization:` ← validator_company / JSON `organization_2` / customer name / "N/A" |
| 2 | REPORT INFORMATION | `Report ID:` ← JSON `report_id` / public id · `Report Date:` ← `report_date` / timestamp · `Software Version:` ← `"{software_version or 'D-Secure 1.0.0'} {product_version}"` (trailing space trimmed in v1) · `Customer Name:` ← `customer_name` ("Customer") · `Customer Address:` ← `customer_address` ("N/A") · `Diagnostic:` ← diagnostic type ("System Diagnostic Suite") · `Status:` ← server result status, else JSON `status`, else "Completed" |
| 3 | Statement (9 pt) | "I hereby state that the diagnostic process has been carried out in accordance with the given specifications." |
| 4 | Signature row | captions `DIAGNOSTIC TECH SIGNATURE` / `VALIDATOR SIGNATURE` |

**Page 2+**
| # | Section | Content |
|---|---|---|
| 5 | HARDWARE INFORMATION (block, 19 rows) | Manufacturer, Chassis Type, Model Name, UUID, System Serial, Chassis Serial (← `chassis_serial`, else stored machine id), Board Serial, SKU Number, Memory (RAM), Memory Bank (← `memory_banks[]` as `"{manufacturer }{size} {memory_type} {speed}, Form: {form_factor}, Serial: {serial}"` joined " \| "), Processor (format as Drive; fallback `device_info` of `diagnostic_results[]` element named `CPU`), BIOS (Drive format, always printed), BIOS Features, Graphics Card, Sound Cards (← `sound_cards[]` joined ", "), Optical Drive, USB Controller, Media Source ("SYSTEM"), Media Destination ("CLOUD"); others "N/A" |
| 6 | STORAGE DEVICES (only if `disks[]`) | 11 pt bold + rule; one block per disk titled with label `"Disk [{index}] {model} {media_type} {size} ({interface_type})"`: `Model:` (label) · `Serial:` · `Size:` · `Interface:` · `Media Type:` · `Sector Size:` · `SMART Status:` · `Encryption:` |
| 7 | NETWORK ADAPTERS (only if any) | bullets `• {interface_name} ({interface_status}), MAC: {mac_address}, IP: {ip_address}` 9 pt |
| 8 | HARDWARE TEST RESULTS | per component (ordered map: first position, last value wins): row 3:1 — name 10 pt bold, result right-aligned 10 pt bold, green if `successful`/`passed`/`pass`; sub-tests indented 12 pt in 4-col grid, 2 per row: `  {name}:` 9 pt grey (#757575) / status 9 pt (green on `pass`/`passed`). Source `diagnostic_results[]` (`component_name`, `result`, `sub_tests[{name, result\|status, note}]` → `"{name}: {status}"` / `"... ({note})"`, else `details{}` props); legacy `hardware_tests[]` only when `diagnostic_results` absent |
| 9 | S.M.A.R.T HEALTH DATA (new page, only if `smart_health`) | per drive (array or single object): title `model`/`drive_id`/"Drive"; rows Drive ID, Serial, Health (`health_status`), Temperature, Power-On Hours, Power Cycles, Wear, Available Spare, Media Errors, Firmware, Transport, Assessment (`overall_assessment`); then `checks[]` lines `  {name}: {result}` (+ ` ({note})`) 8 pt, green on pass |

---

## 6. File Eraser — `file.v1` (from `GenerateReport` + `ParseDSecureReportData`, contract file §10)

Title **"DATA ERASURE CERTIFICATE"** (hard-coded; `report_title`/`header_text` not printed, parity). Footer sentence: "The information contained in this report is digitally protected and generated by the D-Secure data erasure process."

**Page 1**
| # | Block | Labels ← source (default) |
|---|---|---|
| 1 | PERSONNEL & AUTHORITY | `Performed by` ← technician_name ("Technician") · `Validated by` ← validator_name ("Validator") · `Dept` ← technician_dept ("N/A") · `Dept` ← validator_dept ("N/A") · `Company` ← technician_company / customer name / "N/A" · `Company` ← validator_company / customer name / "N/A" (labels without colon, parity) |
| 2 | ASSET INFORMATION | `Computer:` ← computer/host name ("Unknown") · `OS:` ← `os_version`, else `os` ("N/A") · `Manufacturer:` ← `manufacturer` unless equal (case-insensitive) to computer name ("N/A") · `MAC Address:` ← `mac_address` ("Unknown") |
| 3 | ERASURE EXECUTION DETAILS | `Erasure Method:` ← JSON `eraser_method`, else stored method · `Erasure Type:` ← `Erasure_Type` / `erasure_type` ("Unknown") · `Total Files:` ← `total_files` (0) · `Successful:` ← `erased_files` (0) · `Failed Files:` ← `failed_files` (0) · `Verification:` ← validation method ("Not Specified") · `Start Time:` ← `Eraser_Start_Time`/`eraser_start_time` ("N/A") · `End Time:` ← `Eraser_End_Time`/`eraser_end_time` ("N/A") · `Report ID:` ← public id (v1; .NET printed JSON `report_id` or row id) · `Report Date:` ← JSON `datetime`, else report timestamp |
| 4 | AUDIT PROOF (11 pt + rule) | 2-col 1.5 : 6.5: "Verification Code:" 9 pt bold / `<code>` + signature 7 pt grey |
| 5 | Statement (9 pt) | "I hereby certify that the data erasure process detailed above has been executed in accordance with defined standards, ensuring that all data has been permanently and irreversibly erased." |
| 6 | Signature row | `TECHNICIAN` / `VALIDATOR` |

**Page 2 "Annexure: Detailed Erasure Log"** (11 pt bold + rule). Empty → italic 10 pt "No erasure log entries available.". Table header cells white text on black, 10 pt bold, padding 2; body 9 pt. Variant chosen from `erasure_type`:
| Variant | Condition (case-insensitive) | Columns (relative widths) |
|---|---|---|
| A files | contains `File` or `Scheduled`, or equals `file_folder` / `scheduled_task` | `Files & Folders Path` 350 · `Size` 100 · `Status` 80 |
| B deleted data | contains `DeletedData` / `Deleted Data`, or equals `deleted_data` | `Target` 250 · `Free Space` 80 · `Total Free Sectors` 120 · `Erased Sectors` 100 · `Status` 80 |
| C file-like generic | contains `Folder` / `Cloud` (A/B not matched) | first header `Cloud Target` (Cloud) / `Scheduled Task` / `Volume / Drive` (contains "Free Space") / `File / Folder Path` / else `Target Path` · `Size` · `Status` (400/100/100) |
| D volumes | otherwise | `Target Volume` 270 · `Capacity` 80 · `Total Sectors` 100 · `Erased Sectors` 100 · `Status` 80 |
Row fields: target ← `target`/`path`/`file`/`"{Cloud_Service} ({cloud_remote_name})"`/cloud service/"Unknown" (SafePath); size ← first of `size_str`, `free_space`, `dummy_file_size`, `size`, `capacity`, else `total_sectors × 512` as `x.xx GB` (≥ 1 GB) / `x.xx MB`; total sectors ← `total_sectors`/`erased_sectors`/`sectors_erased` ("N/A" for file/folder/scheduled/cloud types, else "Unknown"); erased sectors ← `erased_sectors`/`sectors_erased`; status ← `status`. Root may be a bare JSON array (then totals derived: erased = status `Erased`/`Completed`). Max rows rendered: all (client paginates); server caps log at 50,000 rows in `render_data` (larger → "… N more entries in the downloadable JSON", **new**, DV-6).
Empty/unparseable JSON: .NET printed a one-line default certificate with the owner email as "Computer" — **not ported** (finalize refuses empty reports; DV-4).

---

## 7. System Cleaner — `cleaner.v1` (from `GenerateSystemCleanerReport`)

Title **"SYSTEM CLEANER CERTIFICATE"**. Input = `reportDetails` object if present, else root; every property → text; `erasure_log[]` → annexure. Footer sentence (parity, .NET text): "The information contained in this report is digitally protected and generated by the D-Secure system diagnostic process." (wording says "diagnostic" — open question Q2).
| # | Block | Labels ← source (default) |
|---|---|---|
| 1 | PERSONNEL & AUTHORITY | `Performed by` ← JSON `technician_name`, else branding, else "N/A" · `Validated by` ← JSON `validator_name` / branding / "N/A" · `Dept` ← `technician_dept` / branding / "N/A" · `Dept` ← `validator_dept` · `Company` ← `technician_company` / branding / customer name / "N/A" · `Company` ← `validator_company` (JSON wins over branding here: .NET order kept) |
| 2 | ASSET INFORMATION | `Computer:` ← `computer_name` · `OS:` ← `os_version` · `Manufacturer:` ← `"{manufacturer} ({model})"` / `manufacturer` / "N/A" · `MAC Address:` ← `mac_address` |
| 3 | ERASURE EXECUTION DETAILS | `Erasure Method:` ← `eraser_method` · `Erasure Type:` ← `erasure_type` · `Total Volumes:` ← `total_files`, else `driveCount` · `Verification:` ← `validation_method` · `Start Time:` ← `Eraser_Start_Time` · `End Time:` ← `Eraser_End_Time` · `Report ID:` ← public id (v1) · `Report Date:` ← `datetime` (all "N/A") |
| 4 | AUDIT PROOF | as §6 |
| 5 | Statement | "I hereby certify that the system diagnostic process detailed above has been executed in accordance with defined standards, ensuring that all unnecessary data has been permanently and irreversibly erased." (parity; Q2) |
| 6 | Signature row | `TECHNICIAN` / `VALIDATOR`; images: JSON `technician_image` / `validator_image` (data URI) override branding |
| 7 | "Annexure: Detailed Erasure Log" (new page, only if log) | Variant D columns (`Target Volume`, `Capacity` ← `capacity`, `Total Sectors`, `Erased Sectors`, `Status`) |
CVRA subtype: .NET generates **no** PDF for CVRA reports (stored only). v1: `cleaner_cvra` has no template (data + verify only) unless owner asks (Q3).

---

## 8. Autopilot — `autopilot.v1` and `autopilot_consolidation.v1` (from `Reports/Documents/*`)

### 8.1 Single device report (`AutopilotReportDocument`)
| Element | Spec |
|---|---|
| Page | US Letter; margins left/right/top 40 pt, bottom 60 pt; default text 9 pt Arial → **Liberation Sans** (metric-compatible), black |
| Background | Watermark image (opacity-processed variant), width 350 pt centred; none → built-in `autopilot-watermark.png` |
| Header | Row: left = left logo height 24 pt (default `logo.png`; none → text "D-Secure" 24 pt bold `#0B5FA5`); right = right logo height 24 pt (default `autopilot-right-logo.png`; none → text "D-SecureErase" 16 pt semibold); bottom padding 10 |
| Title | "AUTOPILOT REPORT" 14 pt bold centred, bottom padding 15 |
| Section | Title 10 pt bold, 1 pt rule, content top padding 6; field line = label column 90 pt `"{label}:"` 8 pt bold + value 8 pt (empty → "-") |
| PERSONNEL & AUTHORITY | Two columns: [`Performed by` ← technician_name · `Dept` ← technician_dept · `Company` ← technician_company] [`Validated by` · `Dept` · `Company` ← validator_*] (defaults "N/A") |
| ASSET INFORMATION | Two columns: [`Model` ← model ("Unknown") · `Manufacturer` ← manufacturer text before " - " / " – " · `Chassis Type` (phrase "The device enclosure is identified as a " and dots stripped; "Unknown") · `SKU Number` (phrase "The manufacturer-assigned System SKU / Board is " stripped) · `System Serial` ("Unknown") · `UUID` ("Unknown")] [`BIOS Version` · `BIOS Date` · `BIOS Manufacturer` (7-branch BIOS string parser, contract autopilot §9) · `TPM Status` (first comma part; "2.0" if ready/true/enabled; strip "TPM ") · `BIOS Lock` ("Unlocked" if contains not set/unlocked/no security/no password; "Locked" if is set/locked/password set; else raw; "Unknown")] |
| AUTOPILOT EXECUTION DETAILS | [`Start Time` ← device created · `End Time` ← terminal status time · `Status` = "Completed"] [`Report ID` ← v1 public id (.NET: first 8 hex of device id upper-case; kept as alias) · `Autopilot Status` ← display status (Enrolled / Unenrolled / Processing; contract autopilot §1.6), colour `#006400` if contains "unenrolled", red `#F44336` if contains "enrolled" · `Software Version` ← "D-Secure Autopilot Detector v1.0.0.0" (or tool-reported version)] |
| CUSTOM FIELDS (only if any) | 3 fields per row, field lines; source `custom_fields` object of strings (non-string value → whole block omitted in .NET; v1: values stringified, DV-5) |
| AUDIT PROOF | Row: "Digital Identifier:" 9 pt bold (100 pt) + `<code>` 6 pt grey (v1 code; legacy RSA identifier printed as a second line "Legacy identifier: …" only for migrated devices) |
| Statement | "I hereby state that the process has been carried out in accordance with the given specifications." 8 pt centred, padding top 10 bottom 20 (model default actually used by .NET) |
| Signatures | Row: spacer · 160 pt block [signature image height 40, or placeholder text "Sample Signature" 18 pt script font, blue `#1976D2`; 1 pt rule; "TECHNICIAN SIGNATURE" 8 pt bold] · spacer · 160 pt block [same, "VALIDATOR SIGNATURE"] · spacer (names not printed, parity) |
| Footer | 1 pt rule; row: left 80 pt = **QR** height 60 (v1 QR content §3) · centre "Digital ID: `<code>`" 5.5 pt grey · right "Page n" 9 pt; then sentence "The information contained in this report is digitally protected and generated by the D-Secure data erasure process." 8 pt grey centred; + v1 verify line |
| Dates | .NET printed UTC values with a literal "IST" suffix (bug). v1 prints tenant timezone with the real zone abbreviation (DV-2); the signed legacy digital identifier string is untouched |

### 8.2 Consolidation report (`AutopilotConsolidationDocument`)
| Element | Spec |
|---|---|
| Title | "Autopilot Consolidation Report" 16 pt bold centred |
| ASSET INFORMATION | 11 pt bold title + rule; per device: mini header "`{n}{st|nd|rd|th}` Device" 10 pt bold; two columns of field lines (label 90 pt, 9 pt): [`Manufacturer` · `Model` · `Status` (colour rule as 8.1)] [`System Serial` · `UUID` · `BIOS Lock`]; 0.5 pt light grey divider (#E0E0E0) between devices |
| Signature strip | Row: "**Date :** `<date>`" · 30 pt · [technician signature image h38 or empty; rule `#1F2933`; "Technician" semibold] · 30 pt · [validator, "Validator"] |
| Footer | Rule `#E3E8EF`; row: left 90 pt left logo h20 or "D-Secure" 12 pt bold `#1F2933`; middle footer note 7 pt `#6B7280`: "The information contained in this report is digitally protected and has been generated by the D-Secure process. D-Secure is an innovation from D-Secure Technologies."; right "Page n" 8 pt muted; + v1 verify line and QR (QR is new here, DV-1) |
| Data | Server returns a signed **batch** (`/autopilot/consolidation-certificates`, ≤ 500 devices per document; each row = that device's signed certificate fingerprint) |

---

## 9. Formatting rules (all templates)
| Item | .NET | v1 |
|---|---|---|
| Dates (server-formatted) | `MMMM dd, yyyy HH:mm:ss` in host culture, UTC values, no zone (Autopilot: literal "IST") | `MMMM dd, yyyy HH:mm:ss zzz` en-US month names, **tenant timezone** (`tenant_settings.timezone`), real abbreviation (e.g. "October 20, 2026 15:45:30 IST"). App-supplied date strings (`report_date`, `start_time`, `datetime`) printed **verbatim** (parity) |
| Numbers from JSON | JSON text | same |
| Missing | per field default (tables) | same; `""` → "N/A" (DV-3) |
| Masking | none in PDF | none in the owner's PDF (owner sees own data); public verify page masks serials (last 4) |
| Language | English labels | same; no i18n in v1 |

## 10. Assets and fonts
| Asset (copy from .NET `Defaults/`, SHA-256 pinned in the template package) | Used by |
|---|---|
| `logo.png` | Default left logo (all) |
| `EraseLogo.png` | Default right logo (File, Cleaner) |
| `drive-eraser.png` | Default right logo (Drive, Diagnostic) |
| `watermark.png` | Default watermark (File, Cleaner) |
| `drive-eraser-watermark.png` | Default watermark (Drive, Diagnostic) |
| `signsample.png` | Default signature images (clean layout) |
| `DSecureLogo.png` | QR centre logo |
| `autopilot-right-logo.png`, `autopilot-watermark.png` | Autopilot defaults |
Fonts: Liberation Sans (Regular/Bold/Italic) and Liberation Mono (SIL OFL 1.1; bundle). Arial → Liberation Sans, Courier New → Liberation Mono. "Brush Script MT" placeholder (proprietary) → an OFL script font chosen by the frontend team (licence check needed; not verified). Asset ownership/licence of the D-Secure PNGs: assumed D-Secure-owned (not verified).

## 11. Golden fixtures and acceptance
- `fixtures/pdf/<template_id>/<case>.json` (raw report JSON, anonymised) + `<case>.render.json` (expected `render_data`) + `<case>.text.txt` (expected text extraction, reading order) + `<case>.dotnet.png` (reference page images rendered once from the .NET QuestPDF output by the main session on non-production data; **not produced yet**).
- Cases per template: full data; minimal data (all defaults); custom branding (all slots); no branding; long values (SafePath, wrapping); many rows (pagination); each File Eraser annexure variant A-D; Diagnostic with/without `diagnostic_results`; Drive with `smart_health`; Autopilot each status colour; consolidation 1 / 25 devices.
- Server CI: mapper(raw) == expected render_data (byte-equal JCS) for every fixture.
- Client CI (dashboard / apps / verify page): text extraction == `<case>.text.txt`; visual diff vs `.dotnet.png` ≤ threshold (proposal: ≤ 2% pixels per page at 100 dpi; tune in Phase 3). Verify page renders the same output as the dashboard for the same fixture.

## 12. Deliberate deviations from .NET (bugs / improvements; owner may veto)
| # | .NET | v1 | Why |
|---|---|---|---|
| DV-1 | QR → `{QrReport:BaseUrl}/{id}` (or Autopilot host); none on consolidation | QR → new verify URL with fingerprint; legacy URLs redirect; QR also on consolidation | Owner asked for QR/verify footer |
| DV-2 | UTC printed with "IST"/no zone; host culture | Tenant timezone, real zone, en-US | Correctness |
| DV-3 | Empty cells when JSON key missing (mapper `""`) | "N/A" | Readability |
| DV-4 | Empty/unparseable File Eraser report → one-line certificate with owner email as "Computer"; PDFs for RESERVED/PENDING rows | No certificate for unfinished/empty reports | Bugs (contract file §10.2, drive §9) |
| DV-5 | Autopilot custom fields block vanishes if any value is not a string | Values stringified | Bug |
| DV-6 | Unbounded erasure log | Server cap 50,000 rows + note | 512 MB / client memory |
| DV-7 | Public PDF default company = owner email (PII) | "N/A" | Bug (contract file §8.3) |
| DV-8 | "Verification Code" = RSA signature over a 15-field subset (not verifiable publicly) | Fingerprint + Ed25519 signature over full render data | Security |

## 13. Open questions (owner / frontend team)
- **Q1** Renderer library per client (browser PDF lib, desktop app native libs): frontend/app team choice; must hit §11 acceptance.
- **Q2** System Cleaner text says "system diagnostic process" twice (footer + statement): keep exact .NET wording (parity, current default) or correct to "system cleaning process"?
- **Q3** CVRA reports: PDF needed (none today)?
- **Q4** Freeze reports: no PDF in .NET; keep data-only?
- **Q5** D-58 email attachments (worker) vs link; D-62 snapshot vs current branding; D-60 verify host name.

## 14. Not verified
- Visual output of the .NET templates (no PDF rendered); QuestPDF colour constants assumed Material palette (Green.Medium #4CAF50, Red.Medium #F44336, Grey.Darken2 #616161, Grey.Darken1 #757575, Grey.Lighten2 #E0E0E0, Blue.Darken2 #1976D2).
- `ImageCompressionHelper` formats (decompress, background removal, opacity value); `QrCodeHelper` QR parameters (error-correction level, logo size).
- Remainder of Drive `MapToReportData` after the parts read (processor/memory/BIOS/erasure_results formatting taken from the drive contract §9).
- Real report JSON key coverage in production (fixtures will come from anonymised samples via the main session).
- Licence of the bundled D-Secure images and of the script font replacement.
