package xyz.dnstt.app

import android.util.Log
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.ChannelDirectTCPIP
import kotlinx.coroutines.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.Security
import java.util.Properties
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SSH Tunnel Client that creates a local SOCKS5 proxy through SSH dynamic port forwarding.
 *
 * Flow:
 * 1. DNSTT creates a raw TCP tunnel on 127.0.0.1:7001, forwarded by the remote
 *    dnstt-server directly to its sshd (e.g. 127.0.0.1:22 on the server).
 * 2. This SSH client connects to 127.0.0.1:7001 (which is sshd, reached through DNSTT).
 * 3. Sets up SSH dynamic port forwarding (-D equivalent).
 * 4. Creates a local SOCKS5 proxy on the requested port (proxy mode: the user's
 *    configured proxy port; VPN mode: the fixed internal port DnsttVpnService expects).
 * 5. User apps (or DnsttVpnService, in VPN mode) connect to that local SOCKS5 proxy.
 */
class SshTunnelClient {
    companion object {
        private const val TAG = "SshTunnelClient"

        // DNSTT tunnel endpoint - SSH server is accessible through this internal port
        private const val DNSTT_TUNNEL_HOST = "127.0.0.1"
        private const val DNSTT_TUNNEL_PORT = 7001

        // DnsttVpnService consumes the SSH SOCKS5 proxy on this port.
        private const val SOCKS5_PROXY_PORT = 7000

        // SSH over a DNS tunnel is much slower than a normal network hop: small
        // per-query payload, and round trips that can take seconds once the
        // transport's idle poll delay backs off. A full JSch connect() needs more
        // room than a default SSH client would ever need.
        private const val TUNNEL_CONNECT_TIMEOUT_MS = 60000
        private const val CHANNEL_CONNECT_TIMEOUT_MS = 15000
        private const val CHANNEL_RETRY_COUNT = 2
        private const val CHANNEL_RETRY_DELAY_MS = 100L

        // Broad, modern algorithm lists (not minimized): prioritize compatibility
        // with real OpenSSH servers over shrinking the handshake payload size.
        private const val KEX_ORDER =
            "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384," +
                "ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512," +
                "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"
        private const val CIPHER_ORDER =
            "aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr"

        init {
            // JSch relies on the JVM's registered security providers to negotiate
            // KEX/cipher/host-key algorithms. Android's built-in provider (Conscrypt)
            // does not implement several algorithms modern OpenSSH servers prefer or
            // require (e.g. curve25519-sha256, ed25519, chacha20-poly1305). Registering
            // BouncyCastle as an additional (lower-priority) provider lets JSch fall
            // back to it for anything Conscrypt doesn't support.
            try {
                val bcProvider = BouncyCastleProvider()
                if (Security.getProvider(bcProvider.name) == null) {
                    Security.addProvider(bcProvider)
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to register BouncyCastle provider", e)
            }

            // JSch's own runtime check for "is this KEX algorithm actually usable"
            // can incorrectly reject algorithms BC does support on some devices
            // (provider ordering quirks). Disabling it avoids that false negative;
            // an actually-unsupported algorithm will still fail at negotiation time
            // with a clear "Algorithm negotiation fail" instead.
            JSch.setConfig("CheckKexes", "")
            JSch.setConfig("kex", KEX_ORDER)
        }
    }

    private var session: Session? = null
    private var socksServerSocket: ServerSocket? = null
    private var isRunning = AtomicBoolean(false)
    private var socksJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var shareProxyEnabled = false

    var lastError: String? = null
        private set

    /**
     * Connect to SSH server through DNSTT tunnel and start a local SOCKS5 proxy.
     *
     * @param username SSH username
     * @param password SSH password (optional if using key)
     * @param privateKey SSH private key in OpenSSH format (optional if using password)
     * @param shareProxy If true, bind to 0.0.0.0 to allow network access; if false, bind to 127.0.0.1
     * @param socksPort Local port to expose the SOCKS5 proxy on (defaults to [SOCKS5_PROXY_PORT])
     * @return true if connection successful
     */
    suspend fun connect(
        username: String,
        password: String? = null,
        privateKey: String? = null,
        shareProxy: Boolean = false,
        socksPort: Int = SOCKS5_PROXY_PORT
    ): Boolean = withContext(Dispatchers.IO) {
        shareProxyEnabled = shareProxy
        try {
            if (isRunning.get()) {
                Log.w(TAG, "SSH tunnel already running")
                return@withContext true
            }

            lastError = null
            Log.i(TAG, "Connecting SSH through DNSTT tunnel at $DNSTT_TUNNEL_HOST:$DNSTT_TUNNEL_PORT")

            // A real DNS-tunneled SSH connect has been observed to reach a working
            // KEX and then die (EOF) right after - consistent with one-off transport
            // hiccups (packet loss, DPI) rather than a deterministic protocol issue.
            // Retry a few times with a fresh session before giving up.
            val maxAttempts = 3
            var connectedSession: Session? = null
            for (attempt in 1..maxAttempts) {
                val jsch = JSch()

                // Add private key if provided
                if (!privateKey.isNullOrEmpty()) {
                    try {
                        jsch.addIdentity("dnstt_key", privateKey.toByteArray(), null, null)
                        Log.d(TAG, "Added SSH private key")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to add private key: ${e.message}")
                    }
                }

                // Create session connecting THROUGH the DNSTT tunnel (127.0.0.1:7001),
                // which the remote dnstt-server forwards directly to its sshd.
                val attemptSession = jsch.getSession(username, DNSTT_TUNNEL_HOST, DNSTT_TUNNEL_PORT).apply {
                    // Set password if provided
                    if (!password.isNullOrEmpty()) {
                        setPassword(password)
                    }

                    // Configure session
                    val config = Properties().apply {
                        put("StrictHostKeyChecking", "no")
                        put("PreferredAuthentications", "publickey,password,keyboard-interactive")
                        put("compression.s2c", "none")
                        put("compression.c2s", "none")
                        put("kex", KEX_ORDER)
                        put("cipher.s2c", CIPHER_ORDER)
                        put("cipher.c2s", CIPHER_ORDER)
                    }
                    setConfig(config)

                    // Set timeouts
                    timeout = TUNNEL_CONNECT_TIMEOUT_MS
                    setServerAliveInterval(15000) // Keep-alive every 15 seconds
                    setServerAliveCountMax(3)
                }

                Log.i(TAG, "Attempting SSH connection as user '$username' (attempt $attempt/$maxAttempts)...")
                try {
                    attemptSession.connect(TUNNEL_CONNECT_TIMEOUT_MS)
                } catch (e: Exception) {
                    lastError = e.message ?: "Unknown SSH error"
                    Log.w(TAG, "SSH connect attempt $attempt/$maxAttempts failed: $lastError")
                    try { attemptSession.disconnect() } catch (_: Exception) {}
                    if (attempt < maxAttempts) {
                        delay(2000)
                    }
                    continue
                }

                if (attemptSession.isConnected) {
                    connectedSession = attemptSession
                    break
                }
            }

            if (connectedSession == null) {
                lastError = lastError ?: "SSH session failed to connect"
                Log.e(TAG, lastError!!)
                return@withContext false
            }
            session = connectedSession

            Log.i(TAG, "SSH session connected successfully")

            // Start local SOCKS5 proxy with dynamic port forwarding
            startSocksProxy(socksPort)

            isRunning.set(true)
            Log.i(TAG, "SSH tunnel with SOCKS5 proxy started on port $socksPort")

            true
        } catch (e: Exception) {
            lastError = e.message ?: "Unknown SSH error"
            Log.e(TAG, "SSH connection failed: $lastError", e)
            disconnect()
            false
        }
    }

    /**
     * Start local SOCKS5 proxy server that forwards through SSH.
     */
    private fun startSocksProxy(port: Int) {
        // Bind to 0.0.0.0 if sharing is enabled, otherwise bind to localhost only
        val bindAddress = if (shareProxyEnabled) {
            InetSocketAddress(InetAddress.getByName("0.0.0.0"), port)
        } else {
            InetSocketAddress(InetAddress.getByName("127.0.0.1"), port)
        }

        socksServerSocket = ServerSocket().apply {
            reuseAddress = true
            bind(bindAddress)
        }

        Log.i(TAG, "SOCKS5 proxy binding to ${bindAddress.address.hostAddress}:$port (sharing: $shareProxyEnabled)")

        socksJob = scope.launch {
            Log.i(TAG, "SOCKS5 proxy listening on port $port")

            while (isActive && isRunning.get()) {
                try {
                    val clientSocket = socksServerSocket?.accept() ?: break

                    launch {
                        handleSocksClient(clientSocket)
                    }
                } catch (e: IOException) {
                    if (isRunning.get()) {
                        Log.e(TAG, "Error accepting SOCKS connection: ${e.message}")
                    }
                    break
                }
            }
        }
    }

    /**
     * Handle SOCKS5 client connection.
     */
    private suspend fun handleSocksClient(clientSocket: Socket) = withContext(Dispatchers.IO) {
        try {
            val input = clientSocket.getInputStream()
            val output = clientSocket.getOutputStream()

            // SOCKS5 greeting
            val greeting = ByteArray(256)
            val greetingLen = input.read(greeting)

            if (greetingLen < 2 || greeting[0] != 0x05.toByte()) {
                Log.w(TAG, "Invalid SOCKS5 greeting")
                clientSocket.close()
                return@withContext
            }

            // Send no-auth response
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            // Read connection request
            val request = ByteArray(256)
            val requestLen = input.read(request)

            if (requestLen < 4 || request[0] != 0x05.toByte() || request[1] != 0x01.toByte()) {
                Log.w(TAG, "Invalid SOCKS5 request")
                clientSocket.close()
                return@withContext
            }

            // Parse destination
            val (host, port) = when (request[3].toInt() and 0xFF) {
                0x01 -> { // IPv4
                    val addr = "${request[4].toInt() and 0xFF}.${request[5].toInt() and 0xFF}.${request[6].toInt() and 0xFF}.${request[7].toInt() and 0xFF}"
                    val p = ((request[8].toInt() and 0xFF) shl 8) or (request[9].toInt() and 0xFF)
                    Pair(addr, p)
                }
                0x03 -> { // Domain name
                    val domainLen = request[4].toInt() and 0xFF
                    val domain = String(request, 5, domainLen)
                    val portOffset = 5 + domainLen
                    val p = ((request[portOffset].toInt() and 0xFF) shl 8) or (request[portOffset + 1].toInt() and 0xFF)
                    Pair(domain, p)
                }
                0x04 -> { // IPv6
                    Log.w(TAG, "IPv6 not supported")
                    sendSocksError(output, 0x08) // Address type not supported
                    clientSocket.close()
                    return@withContext
                }
                else -> {
                    Log.w(TAG, "Unknown address type")
                    sendSocksError(output, 0x08)
                    clientSocket.close()
                    return@withContext
                }
            }

            Log.d(TAG, "SOCKS5 connect request to $host:$port")

            // Create SSH direct-tcpip channel to forward the connection
            try {
                val currentSession = session
                if (currentSession == null) {
                    Log.e(TAG, "Failed to open SSH channel")
                    sendSocksError(output, 0x01)
                    clientSocket.close()
                    return@withContext
                }

                val channel = openChannelWithRetry(currentSession, host, port)

                // Send success response
                output.write(byteArrayOf(
                    0x05, 0x00, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00, // Bind address (0.0.0.0)
                    0x00, 0x00 // Bind port (0)
                ))
                output.flush()

                // Bidirectional forwarding
                val sshInput = channel.inputStream
                val sshOutput = channel.outputStream

                val job1 = scope.launch {
                    try {
                        val buffer = ByteArray(8192)
                        while (isActive) {
                            val read = input.read(buffer)
                            if (read <= 0) break
                            sshOutput.write(buffer, 0, read)
                            sshOutput.flush()
                        }
                    } catch (e: Exception) {
                        // Connection closed
                    }
                }

                val job2 = scope.launch {
                    try {
                        val buffer = ByteArray(8192)
                        while (isActive) {
                            val read = sshInput.read(buffer)
                            if (read <= 0) break
                            output.write(buffer, 0, read)
                            output.flush()
                        }
                    } catch (e: Exception) {
                        // Connection closed
                    }
                }

                // Wait for either direction to complete
                job1.join()
                job2.cancel()

                channel.disconnect()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to forward to $host:$port: ${e.message}")
                sendSocksError(output, 0x01)
            }

            clientSocket.close()
        } catch (e: Exception) {
            Log.e(TAG, "SOCKS client error: ${e.message}")
            try { clientSocket.close() } catch (_: Exception) {}
        }
    }

    /**
     * Open an SSH direct-tcpip channel with a short retry, absorbing one-off
     * transport hiccups on the DNS tunnel instead of failing the whole SOCKS5
     * request on the first bad round trip.
     */
    private fun openChannelWithRetry(session: Session, host: String, port: Int): ChannelDirectTCPIP {
        var lastException: Exception? = null
        for (attempt in 0..CHANNEL_RETRY_COUNT) {
            if (attempt > 0) {
                Thread.sleep(CHANNEL_RETRY_DELAY_MS)
            }
            try {
                val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                channel.setHost(host)
                channel.setPort(port)
                channel.connect(CHANNEL_CONNECT_TIMEOUT_MS)
                return channel
            } catch (e: Exception) {
                lastException = e
                if (!session.isConnected) throw e // session dead, no point retrying
                Log.w(TAG, "Channel open attempt ${attempt + 1}/${CHANNEL_RETRY_COUNT + 1} failed for $host:$port: ${e.message}")
            }
        }
        throw lastException!!
    }

    private fun sendSocksError(output: java.io.OutputStream, errorCode: Int) {
        try {
            output.write(byteArrayOf(
                0x05, errorCode.toByte(), 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ))
            output.flush()
        } catch (_: Exception) {}
    }

    /**
     * Disconnect SSH session and stop SOCKS5 proxy.
     */
    fun disconnect() {
        Log.i(TAG, "Disconnecting SSH tunnel")
        isRunning.set(false)

        socksJob?.cancel()
        socksJob = null

        try {
            socksServerSocket?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing SOCKS server: ${e.message}")
        }
        socksServerSocket = null

        try {
            session?.disconnect()
        } catch (e: Exception) {
            Log.e(TAG, "Error disconnecting SSH: ${e.message}")
        }
        session = null

        Log.i(TAG, "SSH tunnel disconnected")
    }

    /**
     * Check if SSH tunnel is connected.
     */
    fun isConnected(): Boolean {
        return isRunning.get() && session?.isConnected == true
    }

    /**
     * Clean up resources.
     */
    fun cleanup() {
        disconnect()
        scope.cancel()
    }
}
