package com.example.ui

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.analyzer.ApkAuditReport
import com.example.analyzer.ApkPackageInspector
import com.example.analyzer.BinaryAnalysisResult
import com.example.analyzer.BinaryAnalyzer
import com.example.analyzer.BinaryTargetPreset
import com.example.analyzer.HexDumpRow
import com.example.analyzer.InstalledPackageBrief
import com.example.analyzer.StringCategory
import com.example.analyzer.WebBehaviorTracer
import com.example.analyzer.WebTraceResult
import com.example.data.EvidenceDatabase
import com.example.data.EvidenceReportEntity
import com.example.data.EvidenceRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.min

enum class ReaMainTab(val route: String, val title: String, val bnSubtitle: String) {
    BINARY("binary_inspector", "Binary & Hex", "বাইনারি ও হেক্স বিশ্লেষণ"),
    APK("apk_forensics", "APK & DEX", "অ্যাপ ও ডেক্স ডিসেকশন"),
    WEB("web_tracer", "Web & API", "ওয়েব ও নেটওয়ার্ক ট্রেস"),
    VAULT("evidence_vault", "Evidence Vault", "প্রমাণ ও রিপোর্ট ভল্ট")
}

data class ReaUiState(
    val currentTab: ReaMainTab = ReaMainTab.BINARY,
    val binaryPresets: List<BinaryTargetPreset> = emptyList(),
    val selectedPresetId: String = "self_dex",
    val isLoadingBinary: Boolean = false,
    val binaryResult: BinaryAnalysisResult? = null,
    val binarySubTab: Int = 0, // 0=Headers, 1=Hex Dump, 2=Strings, 3=Entropy
    val minStringLength: Int = 5,
    val selectedStringCategory: StringCategory = StringCategory.ALL,
    val stringSearchQuery: String = "",
    val hexSearchQuery: String = "",
    val hexStartOffset: Int = 0,
    val currentHexRows: List<HexDumpRow> = emptyList(),

    // APK & Package Audit
    val inspectablePackages: List<InstalledPackageBrief> = emptyList(),
    val selectedPackageName: String = "",
    val apkAuditReport: ApkAuditReport? = null,
    val isLoadingApk: Boolean = false,
    val apkSubTab: Int = 0, // 0=Archive & DEX, 1=Permissions, 2=Components, 3=Certificate

    // Web & API Tracer
    val targetUrlInput: String = "https://api.github.com/repos/morluto/rea",
    val isTracingUrl: Boolean = false,
    val webTraceResult: WebTraceResult? = null,
    val webSubTab: Int = 0, // 0=Protocol & Timing, 1=Security Headers, 2=DOM/Keys, 3=Replay Code

    // Vault filter & feedback
    val vaultCategoryFilter: String = "ALL",
    val vaultSearchQuery: String = "",
    val selectedEvidenceReport: EvidenceReportEntity? = null,
    val statusBannerMessage: String? = null
)

class ReaInspectorViewModel(
    private val appContext: Context,
    private val repository: EvidenceRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(ReaUiState())
    val uiState: StateFlow<ReaUiState> = _uiState.asStateFlow()

    val savedReports: StateFlow<List<EvidenceReportEntity>> = repository.allReports
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    init {
        initializeToolkit()
    }

    private fun initializeToolkit() {
        viewModelScope.launch(Dispatchers.IO) {
            val presets = ApkPackageInspector.getBuiltInTargets(appContext)
            val packages = ApkPackageInspector.listInspectablePackages(appContext)
            val initialBinary = ApkPackageInspector.loadPresetBinary(appContext, "self_dex", 5)
            val initialHex = BinaryAnalyzer.generateHexRows(initialBinary.rawSampleBytes, 0, 100, "")
            val initialApkAudit = ApkPackageInspector.inspectPackage(appContext, appContext.packageName)

            _uiState.update { state ->
                state.copy(
                    binaryPresets = presets,
                    selectedPresetId = "self_dex",
                    binaryResult = initialBinary,
                    currentHexRows = initialHex,
                    inspectablePackages = packages,
                    selectedPackageName = appContext.packageName,
                    apkAuditReport = initialApkAudit
                )
            }

            // Seed initial real evidence snapshot if database is empty
            if (repository.getCount() == 0) {
                seedInitialEvidence(initialBinary, initialApkAudit)
            }

            // Perform initial live trace on morluto/rea GitHub API
            runWebTrace("https://api.github.com/repos/morluto/rea")
        }
    }

    private suspend fun seedInitialEvidence(
        dexBinary: BinaryAnalysisResult,
        apkAudit: ApkAuditReport
    ) {
        val dexFindings = buildString {
            appendLine("• Target: ${dexBinary.sourceName}")
            appendLine("• Format: ${dexBinary.formatName} (${dexBinary.magicHex})")
            appendLine("• SHA-256: ${dexBinary.sha256Hash}")
            appendLine("• Shannon Entropy: ${"%.2f".format(dexBinary.overallEntropy)} bits/byte (${dexBinary.entropyAssessment})")
            dexBinary.headerFields.forEach { field ->
                appendLine("• ${field.name} [${field.offsetRange}]: ${field.decodedValue}")
            }
        }
        repository.insert(
            EvidenceReportEntity(
                title = "Self APK: classes.dex Bytecode Dissection",
                category = "DEX_BINARY",
                magicFormat = "${dexBinary.formatBadge} • ${dexBinary.magicHex}",
                summaryMetrics = "Entropy ${"%.2f".format(dexBinary.overallEntropy)} b/B • ${dexBinary.extractedStrings.size} Strings • ${dexBinary.headerFields.size} Header Fields",
                detailedEvidence = dexFindings,
                engineerNotes = "Auto-captured live Dalvik Executable header & string table evidence from running APK.",
                isPinned = true
            )
        )

        val apkFindings = buildString {
            appendLine("• Package: ${apkAudit.packageName} (v${apkAudit.versionName})")
            appendLine("• SDK Target: minSdk ${apkAudit.minSdk} / targetSdk ${apkAudit.targetSdk}")
            appendLine("• Archive Entries: ${apkAudit.totalArchiveEntries} files (${apkAudit.dexCount} DEX, ${apkAudit.nativeSoCount} Native .so)")
            appendLine("• Certificate SHA-256: ${apkAudit.certSha256}")
            appendLine("• Declared Components: ${apkAudit.components.size} (${apkAudit.components.count { it.isExported }} exported)")
            appendLine("• Requested Permissions: ${apkAudit.permissions.joinToString { it.shortName }}")
        }
        repository.insert(
            EvidenceReportEntity(
                title = "APK Security & Manifest Audit (${apkAudit.appLabel})",
                category = "APK_AUDIT",
                magicFormat = "APK Container • minSdk ${apkAudit.minSdk} / targetSdk ${apkAudit.targetSdk}",
                summaryMetrics = "${apkAudit.totalArchiveEntries} Entries • ${apkAudit.permissions.size} Perms • ${apkAudit.components.size} Components",
                detailedEvidence = apkFindings,
                engineerNotes = "Baseline package manifest, signing certificate, and exported component surface audit.",
                isPinned = false
            )
        )
    }

    fun selectMainTab(tab: ReaMainTab) {
        _uiState.update { it.copy(currentTab = tab, selectedEvidenceReport = null) }
    }

    fun selectBinarySubTab(index: Int) {
        _uiState.update { it.copy(binarySubTab = index) }
    }

    fun selectApkSubTab(index: Int) {
        _uiState.update { it.copy(apkSubTab = index) }
    }

    fun selectWebSubTab(index: Int) {
        _uiState.update { it.copy(webSubTab = index) }
    }

    fun selectBinaryPreset(presetId: String) {
        _uiState.update { it.copy(selectedPresetId = presetId, isLoadingBinary = true, hexStartOffset = 0) }
        viewModelScope.launch(Dispatchers.IO) {
            val minLen = _uiState.value.minStringLength
            val result = ApkPackageInspector.loadPresetBinary(appContext, presetId, minLen)
            val hexRows = BinaryAnalyzer.generateHexRows(result.rawSampleBytes, 0, 100, _uiState.value.hexSearchQuery)
            _uiState.update {
                it.copy(
                    isLoadingBinary = false,
                    binaryResult = result,
                    currentHexRows = hexRows
                )
            }
        }
    }

    fun inspectExternalUri(uri: Uri) {
        _uiState.update { it.copy(isLoadingBinary = true, selectedPresetId = "custom_uri", hexStartOffset = 0) }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val cr = appContext.contentResolver
                var displayName = uri.lastPathSegment ?: "external_binary.bin"
                var fileSize = 0L
                cr.query(uri, null, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                        if (nameIdx >= 0) displayName = cursor.getString(nameIdx) ?: displayName
                        if (sizeIdx >= 0) fileSize = cursor.getLong(sizeIdx)
                    }
                }

                val bytes = cr.openInputStream(uri)?.use { stream ->
                    val out = java.io.ByteArrayOutputStream()
                    val buf = ByteArray(8192)
                    var total = 0
                    val maxRead = 96 * 1024
                    while (total < maxRead) {
                        val r = stream.read(buf, 0, min(buf.size, maxRead - total))
                        if (r <= 0) break
                        out.write(buf, 0, r)
                        total += r
                    }
                    out.toByteArray()
                } ?: ByteArray(0)

                val minLen = _uiState.value.minStringLength
                val result = BinaryAnalyzer.analyzeBytes(
                    sourceName = displayName,
                    sourcePath = uri.toString(),
                    fullSizeBytes = if (fileSize > 0) fileSize else bytes.size.toLong(),
                    bytes = bytes,
                    minStringLength = minLen
                )
                val hexRows = BinaryAnalyzer.generateHexRows(result.rawSampleBytes, 0, 100, "")
                _uiState.update {
                    it.copy(
                        isLoadingBinary = false,
                        binaryResult = result,
                        currentHexRows = hexRows,
                        statusBannerMessage = "Loaded $displayName (${bytes.size} bytes analyzed)"
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isLoadingBinary = false,
                        statusBannerMessage = "Failed to read file: ${e.localizedMessage}"
                    )
                }
            }
        }
    }

    fun updateMinStringLength(length: Int) {
        val currentPreset = _uiState.value.selectedPresetId
        _uiState.update { it.copy(minStringLength = length) }
        if (currentPreset != "custom_uri") {
            selectBinaryPreset(currentPreset)
        } else {
            val currentBytes = _uiState.value.binaryResult?.rawSampleBytes ?: return
            val currentRes = _uiState.value.binaryResult ?: return
            viewModelScope.launch(Dispatchers.Default) {
                val updated = BinaryAnalyzer.analyzeBytes(
                    sourceName = currentRes.sourceName,
                    sourcePath = currentRes.sourcePath,
                    fullSizeBytes = currentRes.totalSizeBytes,
                    bytes = currentBytes,
                    minStringLength = length
                )
                _uiState.update { it.copy(binaryResult = updated) }
            }
        }
    }

    fun updateStringCategory(category: StringCategory) {
        _uiState.update { it.copy(selectedStringCategory = category) }
    }

    fun updateStringSearchQuery(query: String) {
        _uiState.update { it.copy(stringSearchQuery = query) }
    }

    fun updateHexSearchAndOffset(query: String = _uiState.value.hexSearchQuery, offset: Int = _uiState.value.hexStartOffset) {
        val sample = _uiState.value.binaryResult?.rawSampleBytes ?: return
        val clampedOffset = offset.coerceIn(0, (sample.size - 16).coerceAtLeast(0))
        _uiState.update { it.copy(hexSearchQuery = query, hexStartOffset = clampedOffset) }
        viewModelScope.launch(Dispatchers.Default) {
            val rows = BinaryAnalyzer.generateHexRows(sample, clampedOffset, 100, query)
            _uiState.update { it.copy(currentHexRows = rows) }
        }
    }

    fun selectPackageForAudit(packageName: String) {
        _uiState.update { it.copy(selectedPackageName = packageName, isLoadingApk = true) }
        viewModelScope.launch(Dispatchers.IO) {
            val report = ApkPackageInspector.inspectPackage(appContext, packageName)
            _uiState.update { it.copy(apkAuditReport = report, isLoadingApk = false) }
        }
    }

    fun updateTargetUrlInput(url: String) {
        _uiState.update { it.copy(targetUrlInput = url) }
    }

    fun runWebTrace(urlToTrace: String = _uiState.value.targetUrlInput) {
        if (urlToTrace.isBlank()) return
        _uiState.update { it.copy(targetUrlInput = urlToTrace, isTracingUrl = true) }
        viewModelScope.launch {
            val result = WebBehaviorTracer.traceUrl(urlToTrace)
            _uiState.update {
                it.copy(
                    isTracingUrl = false,
                    webTraceResult = result
                )
            }
        }
    }

    fun saveCurrentBinaryEvidence() {
        val bin = _uiState.value.binaryResult ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val category = if (bin.formatBadge.contains("ELF")) "ELF_NATIVE" else "DEX_BINARY"
            val details = buildString {
                appendLine("• Binary Source: ${bin.sourceName}")
                appendLine("• Path: ${bin.sourcePath}")
                appendLine("• Format & Magic: ${bin.formatName} [${bin.magicHex}]")
                appendLine("• Architecture: ${bin.architectureInfo}")
                appendLine("• SHA-256: ${bin.sha256Hash}")
                appendLine("• MD5: ${bin.md5Hash}")
                appendLine("• Entropy: ${"%.2f".format(bin.overallEntropy)} bits/B (${bin.entropyAssessment})")
                appendLine("• Byte Distribution: Printable ${"%.1f".format(bin.printableAsciiPercent)}% | Null ${"%.1f".format(bin.nullBytesPercent)}% | High ${"%.1f".format(bin.highBytesPercent)}%")
                appendLine("\n--- Parsed Header Fields ---")
                bin.headerFields.forEach { f ->
                    appendLine("• ${f.name} (${f.offsetRange}): ${f.decodedValue} [${f.rawHex}]")
                }
                appendLine("\n--- Top Extracted Symbols & Strings ---")
                bin.extractedStrings.take(15).forEach { s ->
                    appendLine("  ${s.offsetHex} [${s.category.label}] ${s.value}")
                }
            }
            repository.insert(
                EvidenceReportEntity(
                    title = "Binary Analysis: ${bin.sourceName}",
                    category = category,
                    magicFormat = "${bin.formatBadge} • ${bin.magicHex}",
                    summaryMetrics = "Entropy ${"%.2f".format(bin.overallEntropy)} b/B • ${bin.extractedStrings.size} Strings • SHA-256 ${bin.sha256Hash.take(10)}…",
                    detailedEvidence = details,
                    engineerNotes = "Captured from Binary & Hex Dissector."
                )
            )
            withContext(Dispatchers.Main) {
                _uiState.update { it.copy(statusBannerMessage = "Saved '${bin.sourceName}' to Evidence Vault") }
            }
        }
    }

    fun saveCurrentApkEvidence() {
        val apk = _uiState.value.apkAuditReport ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val details = buildString {
                appendLine("• App Name: ${apk.appLabel} (${apk.packageName})")
                appendLine("• Version: ${apk.versionName} (Code ${apk.versionCode})")
                appendLine("• SDK Levels: minSdk=${apk.minSdk}, targetSdk=${apk.targetSdk}")
                appendLine("• Base APK Path: ${apk.sourceApkPath} (${apk.apkSizeBytes / 1024} KB)")
                appendLine("• Signing SHA-256: ${apk.certSha256}")
                appendLine("• Archive Breakdown: ${apk.totalArchiveEntries} entries (${apk.dexCount} DEX, ${apk.nativeSoCount} Native .so)")
                appendLine("• Permissions (${apk.permissions.size}): ${apk.permissions.joinToString { it.shortName }}")
                appendLine("• Exported Surface: ${apk.components.count { it.isExported }} / ${apk.components.size} components exported")
            }
            repository.insert(
                EvidenceReportEntity(
                    title = "APK Audit: ${apk.appLabel} (${apk.packageName})",
                    category = "APK_AUDIT",
                    magicFormat = "APK • minSdk ${apk.minSdk} / targetSdk ${apk.targetSdk}",
                    summaryMetrics = "${apk.totalArchiveEntries} Entries • ${apk.permissions.size} Perms • ${apk.components.size} Components",
                    detailedEvidence = details,
                    engineerNotes = "Captured from APK & DEX Forensics tab."
                )
            )
            withContext(Dispatchers.Main) {
                _uiState.update { it.copy(statusBannerMessage = "Saved APK Audit for '${apk.appLabel}' to Vault") }
            }
        }
    }

    fun saveCurrentWebEvidence() {
        val trace = _uiState.value.webTraceResult ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val details = buildString {
                appendLine("• Target URL: ${trace.targetUrl}")
                appendLine("• Final Resolved URL: ${trace.finalUrl}")
                appendLine("• HTTP Status: ${trace.statusCode} ${trace.statusMessage} (${trace.protocol})")
                appendLine("• TLS Handshake: ${trace.tlsVersion} • Cipher: ${trace.cipherSuite}")
                appendLine("• Timing Breakdown: DNS ${trace.dnsDurationMs}ms | TCP ${trace.connectDurationMs}ms | TLS ${trace.tlsDurationMs}ms | Total ${trace.totalDurationMs}ms")
                appendLine("\n--- Security Header Posture ---")
                trace.securityAudit.forEach { h ->
                    appendLine("• ${h.headerName}: ${if (h.isPresent) "PRESENT (${h.valueOrWarning})" else "MISSING"}")
                }
                appendLine("\n--- Discovered Endpoints (${trace.discoveredEndpoints.size}) ---")
                trace.discoveredEndpoints.take(10).forEach { ep ->
                    appendLine("  -> $ep")
                }
            }
            repository.insert(
                EvidenceReportEntity(
                    title = "Web Trace: ${trace.targetUrl.removePrefix("https://").removePrefix("http://")}",
                    category = "WEB_TRACE",
                    magicFormat = "${trace.protocol} ${trace.statusCode} • ${trace.tlsVersion}",
                    summaryMetrics = "${trace.totalDurationMs}ms RTT • ${trace.responseHeaders.size} Headers • ${trace.discoveredEndpoints.size} Endpoints",
                    detailedEvidence = details,
                    engineerNotes = "Live network & protocol trace captured via OkHttp EventListener."
                )
            )
            withContext(Dispatchers.Main) {
                _uiState.update { it.copy(statusBannerMessage = "Saved Web Trace to Evidence Vault") }
            }
        }
    }

    fun updateVaultCategoryFilter(category: String) {
        _uiState.update { it.copy(vaultCategoryFilter = category) }
    }

    fun updateVaultSearchQuery(query: String) {
        _uiState.update { it.copy(vaultSearchQuery = query) }
    }

    fun selectEvidenceReport(report: EvidenceReportEntity?) {
        _uiState.update { it.copy(selectedEvidenceReport = report) }
    }

    fun togglePinEvidence(report: EvidenceReportEntity) {
        viewModelScope.launch(Dispatchers.IO) {
            val updated = report.copy(isPinned = !report.isPinned)
            repository.update(updated)
            if (_uiState.value.selectedEvidenceReport?.id == report.id) {
                _uiState.update { it.copy(selectedEvidenceReport = updated) }
            }
        }
    }

    fun updateEvidenceNotes(report: EvidenceReportEntity, newNotes: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val updated = report.copy(engineerNotes = newNotes)
            repository.update(updated)
            _uiState.update {
                it.copy(
                    selectedEvidenceReport = if (it.selectedEvidenceReport?.id == report.id) updated else it.selectedEvidenceReport,
                    statusBannerMessage = "Engineer notes updated"
                )
            }
        }
    }

    fun deleteEvidenceReport(id: Int) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.deleteById(id)
            _uiState.update {
                it.copy(
                    selectedEvidenceReport = if (it.selectedEvidenceReport?.id == id) null else it.selectedEvidenceReport,
                    statusBannerMessage = "Evidence report deleted"
                )
            }
        }
    }

    fun clearStatusBanner() {
        _uiState.update { it.copy(statusBannerMessage = null) }
    }

    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val db = EvidenceDatabase.getInstance(context.applicationContext)
            val repo = EvidenceRepository(db.evidenceDao())
            return ReaInspectorViewModel(context.applicationContext, repo) as T
        }
    }
}
