package com.example.analyzer

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.EventListener
import okhttp3.Handshake
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

data class SecurityHeaderAudit(
    val headerName: String,
    val isPresent: Boolean,
    val valueOrWarning: String,
    val purpose: String
)

data class WebTraceResult(
    val targetUrl: String,
    val finalUrl: String,
    val statusCode: Int,
    val statusMessage: String,
    val protocol: String,
    val tlsVersion: String,
    val cipherSuite: String,
    val dnsDurationMs: Long,
    val connectDurationMs: Long,
    val tlsDurationMs: Long,
    val totalDurationMs: Long,
    val contentType: String,
    val contentLengthBytes: Long,
    val responseHeaders: List<Pair<String, String>>,
    val securityAudit: List<SecurityHeaderAudit>,
    val discoveredEndpoints: List<String>,
    val discoveredScriptsAndKeys: List<String>,
    val payloadPreview: String,
    val curlSnippet: String,
    val kotlinOkHttpSnippet: String,
    val errorMessage: String? = null
)

object WebBehaviorTracer {

    val presetEndpoints = listOf(
        "https://api.github.com/repos/morluto/rea" to "GitHub API: morluto/rea Repo Metadata",
        "https://github.com/morluto/rea" to "GitHub Web DOM: morluto/rea HTML & Scripts",
        "https://httpbin.org/get" to "HTTPBin: Live Request & Header Echo",
        "https://www.google.com" to "Google: HTTP/2 + TLSv1.3 Security Audit"
    )

    suspend fun traceUrl(rawUrl: String): WebTraceResult = withContext(Dispatchers.IO) {
        val normalizedUrl = if (
            !rawUrl.startsWith("http://", ignoreCase = true) &&
            !rawUrl.startsWith("https://", ignoreCase = true)
        ) {
            "https://${rawUrl.trim()}"
        } else {
            rawUrl.trim()
        }

        var dnsStart = 0L
        var dnsMs = 0L
        var connectStart = 0L
        var connectMs = 0L
        var tlsStart = 0L
        var tlsMs = 0L

        val eventListener = object : EventListener() {
            override fun dnsStart(call: Call, domainName: String) {
                dnsStart = System.nanoTime()
            }

            override fun dnsEnd(call: Call, domainName: String, inetAddressList: List<InetAddress>) {
                if (dnsStart > 0L) {
                    dnsMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - dnsStart)
                }
            }

            override fun connectStart(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) {
                connectStart = System.nanoTime()
            }

            override fun secureConnectStart(call: Call) {
                tlsStart = System.nanoTime()
            }

            override fun secureConnectEnd(call: Call, handshake: Handshake?) {
                if (tlsStart > 0L) {
                    tlsMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - tlsStart)
                }
            }

            override fun connectEnd(
                call: Call,
                inetSocketAddress: InetSocketAddress,
                proxy: Proxy,
                protocol: Protocol?
            ) {
                if (connectStart > 0L) {
                    connectMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - connectStart)
                }
            }

            override fun connectFailed(
                call: Call,
                inetSocketAddress: InetSocketAddress,
                proxy: Proxy,
                protocol: Protocol?,
                ioe: IOException
            ) {
                if (connectStart > 0L) {
                    connectMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - connectStart)
                }
            }
        }

        val client = OkHttpClient.Builder()
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(12, TimeUnit.SECONDS)
            .followRedirects(true)
            .eventListener(eventListener)
            .build()

        val request = Request.Builder()
            .url(normalizedUrl)
            .header("User-Agent", "REA-Inspector-Android/1.0 (Evidence-Based Reverse Engineering)")
            .header("Accept", "application/json, text/html, */*")
            .get()
            .build()

        val callStart = System.nanoTime()
        try {
            client.newCall(request).execute().use { response ->
                val bodyString = response.body?.string()?.take(24_000) ?: ""
                val totalMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - callStart)
                val handshake = response.handshake
                val tlsVersion = handshake?.tlsVersion?.javaName ?: "Plain HTTP / None"
                val cipherSuite = handshake?.cipherSuite?.javaName ?: "N/A"
                val protocol = response.protocol.toString().uppercase()

                val headersList = mutableListOf<Pair<String, String>>()
                val headers = response.headers
                for (i in 0 until headers.size) {
                    headersList.add(headers.name(i) to headers.value(i))
                }

                val securityAudit = auditSecurityHeaders(headersList.toMap())
                val discoveredEndpoints = extractEndpointsFromBody(bodyString)
                val discoveredScriptsAndKeys = extractScriptsAndJsonKeys(bodyString)

                val contentType = response.header("Content-Type") ?: "unknown"
                val contentLength = response.body?.contentLength()?.takeIf { it >= 0 }
                    ?: bodyString.toByteArray().size.toLong()

                WebTraceResult(
                    targetUrl = normalizedUrl,
                    finalUrl = response.request.url.toString(),
                    statusCode = response.code,
                    statusMessage = response.message.ifEmpty { "OK" },
                    protocol = protocol,
                    tlsVersion = tlsVersion,
                    cipherSuite = cipherSuite,
                    dnsDurationMs = dnsMs,
                    connectDurationMs = connectMs,
                    tlsDurationMs = tlsMs,
                    totalDurationMs = totalMs,
                    contentType = contentType,
                    contentLengthBytes = contentLength,
                    responseHeaders = headersList,
                    securityAudit = securityAudit,
                    discoveredEndpoints = discoveredEndpoints,
                    discoveredScriptsAndKeys = discoveredScriptsAndKeys,
                    payloadPreview = bodyString.take(2800),
                    curlSnippet = buildCurlSnippet(normalizedUrl, headersList),
                    kotlinOkHttpSnippet = buildKotlinSnippet(normalizedUrl),
                    errorMessage = null
                )
            }
        } catch (e: Exception) {
            val totalMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - callStart)
            WebTraceResult(
                targetUrl = normalizedUrl,
                finalUrl = normalizedUrl,
                statusCode = 0,
                statusMessage = "Connection Error",
                protocol = "N/A",
                tlsVersion = "N/A",
                cipherSuite = "N/A",
                dnsDurationMs = dnsMs,
                connectDurationMs = connectMs,
                tlsDurationMs = tlsMs,
                totalDurationMs = totalMs,
                contentType = "N/A",
                contentLengthBytes = 0L,
                responseHeaders = emptyList(),
                securityAudit = emptyList(),
                discoveredEndpoints = emptyList(),
                discoveredScriptsAndKeys = emptyList(),
                payloadPreview = "",
                curlSnippet = buildCurlSnippet(normalizedUrl, emptyList()),
                kotlinOkHttpSnippet = buildKotlinSnippet(normalizedUrl),
                errorMessage = "${e.javaClass.simpleName}: ${e.localizedMessage ?: "Failed to reach endpoint"}"
            )
        }
    }

    private fun auditSecurityHeaders(headerMap: Map<String, String>): List<SecurityHeaderAudit> {
        val lowerMap = headerMap.entries.associate { it.key.lowercase() to it.value }
        val checks = listOf(
            Triple("Strict-Transport-Security", "strict-transport-security", "Enforces HTTPS & prevents TLS downgrade attacks"),
            Triple("Content-Security-Policy", "content-security-policy", "Restricts XSS script execution & frame origins"),
            Triple("X-Frame-Options", "x-frame-options", "Prevents clickjacking via iframe embedding"),
            Triple("X-Content-Type-Options", "x-content-type-options", "Prevents MIME-sniffing of response payloads"),
            Triple("Access-Control-Allow-Origin", "access-control-allow-origin", "Defines cross-origin resource sharing (CORS) policy"),
            Triple("Server", "server", "Reveals backend web server or reverse proxy technology")
        )

        return checks.map { (title, key, purpose) ->
            val value = lowerMap[key]
            SecurityHeaderAudit(
                headerName = title,
                isPresent = value != null,
                valueOrWarning = value ?: "Missing in HTTP response",
                purpose = purpose
            )
        }
    }

    private fun extractEndpointsFromBody(body: String): List<String> {
        val regex = Regex("""https?://[a-zA-Z0-9._/~:-]+|/[a-zA-Z0-9_-]+/[a-zA-Z0-9._/-]+""")
        return regex.findAll(body)
            .map { it.value.trimEnd('.', ',', '"', '\'', ')', ']') }
            .filter { it.length in 8..110 && !it.startsWith("//") }
            .distinct()
            .take(25)
            .toList()
    }

    private fun extractScriptsAndJsonKeys(body: String): List<String> {
        val items = mutableListOf<String>()
        // Extract <script src="...">
        val scriptRegex = Regex("""<script[^>]+src=["']([^"']+)["']""", RegexOption.IGNORE_CASE)
        scriptRegex.findAll(body).forEach { m ->
            items.add("[SCRIPT] ${m.groupValues[1]}")
        }
        // Extract JSON key signatures "key":
        val jsonKeyRegex = Regex(""""([a-zA-Z0-9_]{3,32})"\s*:""")
        jsonKeyRegex.findAll(body).map { it.groupValues[1] }.distinct().take(20).forEach { key ->
            items.add("[JSON_KEY] \"$key\"")
        }
        return items.distinct().take(25)
    }

    private fun buildCurlSnippet(url: String, headers: List<Pair<String, String>>): String {
        val serverHeader = headers.firstOrNull { it.first.equals("server", ignoreCase = true) }?.second
        return buildString {
            appendLine("# Reconstructed by REA Inspector")
            if (serverHeader != null) appendLine("# Target Server: $serverHeader")
            appendLine("curl -i -X GET \\")
            appendLine("  '$url' \\")
            appendLine("  -H 'User-Agent: REA-Inspector-Android/1.0' \\")
            append("  -H 'Accept: application/json, text/html, */*'")
        }
    }

    private fun buildKotlinSnippet(url: String): String {
        return """
            val client = OkHttpClient()
            val request = Request.Builder()
                .url("$url")
                .header("Accept", "application/json, text/html")
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                println("Status: ${'$'}{response.code} Protocol: ${'$'}{response.protocol}")
                println(response.body?.string())
            }
        """.trimIndent()
    }
}
