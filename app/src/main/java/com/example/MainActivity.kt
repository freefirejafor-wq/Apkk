package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Inventory2
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.ReaInspectorViewModel
import com.example.ui.ReaMainTab
import com.example.ui.screens.ApkForensicsScreen
import com.example.ui.screens.BinaryInspectorScreen
import com.example.ui.screens.EvidenceVaultScreen
import com.example.ui.screens.WebTracerScreen
import com.example.ui.theme.MyApplicationTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme(darkTheme = true) {
                ReaInspectorApp()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReaInspectorApp(
    viewModel: ReaInspectorViewModel = viewModel(
        factory = ReaInspectorViewModel.Factory(LocalContext.current)
    )
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val savedReports by viewModel.savedReports.collectAsStateWithLifecycle()
    var showGuideDialog by rememberSaveable { mutableStateOf(false) }

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            viewModel.inspectExternalUri(uri)
        }
    }

    // BackHandler for non-home tabs per Navigation guidelines
    if (uiState.currentTab != ReaMainTab.BINARY && uiState.selectedEvidenceReport == null) {
        BackHandler {
            viewModel.selectMainTab(ReaMainTab.BINARY)
        }
    }

    if (showGuideDialog) {
        ReaCapabilitiesGuideDialog(onDismiss = { showGuideDialog = false })
    }

    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        val isWideScreen = maxWidth >= 600.dp

        Scaffold(
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing),
            topBar = {
                ReaTopHeaderBar(
                    currentTab = uiState.currentTab,
                    vaultCount = savedReports.size,
                    onShowGuide = { showGuideDialog = true }
                )
            },
            bottomBar = {
                if (!isWideScreen) {
                    NavigationBar(
                        containerColor = MaterialTheme.colorScheme.surface,
                        modifier = Modifier.testTag("main_bottom_nav")
                    ) {
                        ReaMainTab.entries.forEach { tab ->
                            NavigationBarItem(
                                selected = uiState.currentTab == tab,
                                onClick = { viewModel.selectMainTab(tab) },
                                icon = {
                                    if (tab == ReaMainTab.VAULT && savedReports.isNotEmpty()) {
                                        BadgedBox(
                                            badge = {
                                                Badge { Text(savedReports.size.toString()) }
                                            }
                                        ) {
                                            Icon(tabIcon(tab), contentDescription = tab.title)
                                        }
                                    } else {
                                        Icon(tabIcon(tab), contentDescription = tab.title)
                                    }
                                },
                                label = { Text(tab.title, style = MaterialTheme.typography.labelMedium) },
                                modifier = Modifier.testTag("nav_tab_${tab.route}")
                            )
                        }
                    }
                }
            }
        ) { innerPadding ->
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                if (isWideScreen) {
                    NavigationRail(
                        containerColor = MaterialTheme.colorScheme.surface,
                        modifier = Modifier
                            .fillMaxHeight()
                            .testTag("main_nav_rail")
                    ) {
                        ReaMainTab.entries.forEach { tab ->
                            NavigationRailItem(
                                selected = uiState.currentTab == tab,
                                onClick = { viewModel.selectMainTab(tab) },
                                icon = { Icon(tabIcon(tab), contentDescription = tab.title) },
                                label = { Text(tab.title) },
                                modifier = Modifier.testTag("rail_tab_${tab.route}")
                            )
                        }
                    }
                }

                Column(modifier = Modifier.weight(1f).fillMaxHeight()) {
                    AnimatedVisibility(visible = uiState.statusBannerMessage != null) {
                        uiState.statusBannerMessage?.let { msg ->
                            Surface(
                                color = MaterialTheme.colorScheme.primaryContainer,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 6.dp)
                                    .clip(RoundedCornerShape(10.dp))
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 8.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = msg,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.weight(1f)
                                    )
                                    IconButton(
                                        onClick = { viewModel.clearStatusBanner() },
                                        modifier = Modifier.size(24.dp)
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Close,
                                            contentDescription = "Dismiss notification",
                                            tint = MaterialTheme.colorScheme.primary,
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }

                    when (uiState.currentTab) {
                        ReaMainTab.BINARY -> BinaryInspectorScreen(
                            presets = uiState.binaryPresets,
                            selectedPresetId = uiState.selectedPresetId,
                            isLoading = uiState.isLoadingBinary,
                            result = uiState.binaryResult,
                            subTab = uiState.binarySubTab,
                            minStringLength = uiState.minStringLength,
                            selectedStringCategory = uiState.selectedStringCategory,
                            stringSearchQuery = uiState.stringSearchQuery,
                            hexSearchQuery = uiState.hexSearchQuery,
                            hexStartOffset = uiState.hexStartOffset,
                            hexRows = uiState.currentHexRows,
                            onSelectPreset = viewModel::selectBinaryPreset,
                            onPickExternalFile = { filePickerLauncher.launch(arrayOf("*/*")) },
                            onSaveEvidence = viewModel::saveCurrentBinaryEvidence,
                            onSelectSubTab = viewModel::selectBinarySubTab,
                            onChangeMinStringLength = viewModel::updateMinStringLength,
                            onSelectStringCategory = viewModel::updateStringCategory,
                            onStringSearchChange = viewModel::updateStringSearchQuery,
                            onHexSearchAndOffsetChange = viewModel::updateHexSearchAndOffset,
                            modifier = Modifier.fillMaxSize()
                        )

                        ReaMainTab.APK -> ApkForensicsScreen(
                            packages = uiState.inspectablePackages,
                            selectedPackageName = uiState.selectedPackageName,
                            report = uiState.apkAuditReport,
                            isLoading = uiState.isLoadingApk,
                            subTab = uiState.apkSubTab,
                            onSelectPackage = viewModel::selectPackageForAudit,
                            onSelectSubTab = viewModel::selectApkSubTab,
                            onSaveApkEvidence = viewModel::saveCurrentApkEvidence,
                            onDissectEntryInHex = { presetId ->
                                viewModel.selectBinaryPreset(presetId)
                                viewModel.selectMainTab(ReaMainTab.BINARY)
                            },
                            modifier = Modifier.fillMaxSize()
                        )

                        ReaMainTab.WEB -> WebTracerScreen(
                            targetUrlInput = uiState.targetUrlInput,
                            isTracing = uiState.isTracingUrl,
                            traceResult = uiState.webTraceResult,
                            subTab = uiState.webSubTab,
                            onUrlChange = viewModel::updateTargetUrlInput,
                            onRunTrace = viewModel::runWebTrace,
                            onSelectSubTab = viewModel::selectWebSubTab,
                            onSaveWebEvidence = viewModel::saveCurrentWebEvidence,
                            modifier = Modifier.fillMaxSize()
                        )

                        ReaMainTab.VAULT -> EvidenceVaultScreen(
                            reports = savedReports,
                            categoryFilter = uiState.vaultCategoryFilter,
                            searchQuery = uiState.vaultSearchQuery,
                            selectedReport = uiState.selectedEvidenceReport,
                            onSelectCategory = viewModel::updateVaultCategoryFilter,
                            onSearchQueryChange = viewModel::updateVaultSearchQuery,
                            onSelectReport = viewModel::selectEvidenceReport,
                            onTogglePin = viewModel::togglePinEvidence,
                            onUpdateNotes = viewModel::updateEvidenceNotes,
                            onDeleteReport = viewModel::deleteEvidenceReport,
                            modifier = Modifier.fillMaxSize()
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ReaTopHeaderBar(
    currentTab: ReaMainTab,
    vaultCount: Int,
    onShowGuide: () -> Unit
) {
    Surface(
        color = MaterialTheme.colorScheme.surface,
        modifier = Modifier
            .fillMaxWidth()
            .border(width = 0.5.dp, color = MaterialTheme.colorScheme.outline)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary)
                )
                Column {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "REA INSPECTOR",
                            style = MaterialTheme.typography.titleLarge,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            text = "v1.0",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(MaterialTheme.colorScheme.primaryContainer)
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                    Text(
                        text = "${currentTab.title} • ${currentTab.bnSubtitle}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.secondary
                    )
                }
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = "$vaultCount Evidence",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.secondary,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
                IconButton(
                    onClick = onShowGuide,
                    modifier = Modifier.testTag("guide_info_button")
                ) {
                    Icon(
                        imageVector = Icons.Default.Info,
                        contentDescription = "How REA Inspector Works",
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
            }
        }
    }
}

@Composable
private fun ReaCapabilitiesGuideDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text("REA Inspector — এটার কাজ কী?", style = MaterialTheme.typography.titleLarge)
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "১. Binary & Hex Dissector (বাইনারি ও হেক্স বিশ্লেষণ):\nযেকোনো APK, classes.dex, AndroidManifest.xml, কিংবা নেটিভ ELF (.so) ফাইলের Magic Header, SHA-256 হ্যাশ, Hex+ASCII ডাম্প, ভেতরের লুকানো Strings/Symbols এবং Shannon Entropy বিশ্লেষণ করে।",
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "২. APK & DEX Forensics (অ্যাপ ও ডেক্স অডিট):\nফোনে থাকা অ্যাপের ভেতরের ফাইল স্ট্রাকচার, ডেক্স মেথড ও ক্লাস সংখ্যা, পারমিশন রিস্ক, এক্সপোর্টেড কম্পোনেন্ট এবং সাইনিং সার্টিফিকেট যাচাই করে।",
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "৩. Web & API Tracer (ওয়েব ও নেটওয়ার্ক ট্রেস):\nযেকোনো ওয়েবসাইট বা API এন্ডপয়েন্টের লাইভ DNS/TCP/TLS টাইমিং, সিকিউরিটি হেডার (CSP, HSTS), লুকানো API রাউট এবং রেডিমেড cURL ও Kotlin কোড তৈরি করে।",
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "৪. Evidence Vault (প্রমাণ ও রিপোর্ট ভল্ট):\nআপনার বিশ্লেষণ করা যেকোনো বাইনারি বা নেটওয়ার্ক রিপোর্ট এবং নোট লোকাল ডেটাবেসে (Room DB) সংরক্ষণ করে রাখে।",
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("বুঝেছি (Got It)")
            }
        }
    )
}

private fun tabIcon(tab: ReaMainTab): ImageVector = when (tab) {
    ReaMainTab.BINARY -> Icons.Default.Memory
    ReaMainTab.APK -> Icons.Default.Android
    ReaMainTab.WEB -> Icons.Default.Language
    ReaMainTab.VAULT -> Icons.Default.Inventory2
}
