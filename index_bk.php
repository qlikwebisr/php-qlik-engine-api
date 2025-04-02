<?php
/**
 * Simple Qlik Sense Engine API Connection in PHP
 * This script connects to the Qlik Sense Engine API on localhost using SSL
 */

// Increase execution time limit for long-running connections
set_time_limit(120); // 2 minutes

// Error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set certificate path
$certPath = __DIR__ . '/certs';

// Function to perform WebSocket handshake and communicate with Qlik Sense Engine
function connectToQlikEngine() {
    global $certPath;
    
    echo "0. Contacting the QIX Engine service...\n";
    
    $host = 'localhost';
    $port = 4747; // Default Qlik Sense Engine port
    $path = '/app/';
    
    // Create SSL context with certificates
    $context = stream_context_create([
        'ssl' => [
            'local_cert' => $certPath . '/client.pem',
            'local_pk' => $certPath . '/client_key.pem',
            'cafile' => $certPath . '/root.pem',
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true
        ]
    ]);
    
    // Connect using SSL to localhost
    echo "1. Creating SSL socket connection...\n";
    $socket = @stream_socket_client(
        'ssl://' . $host . ':' . $port,
        $errno,
        $errstr,
        30,
        STREAM_CLIENT_CONNECT,
        $context
    );
    
    if (!$socket) {
        die("Error connecting to Qlik Sense Engine: $errstr ($errno)\n");
    }
    
    // Set socket timeout to avoid hanging
    stream_set_timeout($socket, 30);
    
    // Perform WebSocket handshake
    echo "2. Performing WebSocket handshake...\n";
    $key = base64_encode(openssl_random_pseudo_bytes(16));
    $headers = [
        "GET $path HTTP/1.1",
        "Host: $host:$port",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: $key",
        "Sec-WebSocket-Version: 13",
        "X-Qlik-User: UserDirectory=internal; UserId=sa_engine"
    ];
    
    fwrite($socket, implode("\r\n", $headers) . "\r\n\r\n");
    
    // Read handshake response with timeout handling
    $response = '';
    $startTime = time();
    $timeoutSeconds = 10;
    
    while (!feof($socket) && (time() - $startTime) < $timeoutSeconds) {
        $line = fgets($socket, 1024);
        if ($line === false) {
            // Check for socket timeout
            $info = stream_get_meta_data($socket);
            if ($info['timed_out']) {
                die("Socket timed out while reading handshake response\n");
            }
            break;
        }
        
        $response .= $line;
        if ($line === "\r\n") break;
    }
    
    // Check if handshake was successful
    if (strpos($response, "101 Switching Protocols") === false) {
        die("WebSocket handshake failed: " . $response);
    }
    
    echo "3. Connected! WebSocket handshake successful\n";
    
    // Send a simple JSON request to the Qlik Engine
    $data = '{}'; // Empty JSON object
    
    // Format data according to WebSocket protocol (simplified)
    $frame = createWebSocketFrame($data);
    fwrite($socket, $frame);
    
    echo "4. Message sent to Qlik Engine\n";
    
    // Read response with timeout handling
    $response = readWebSocketFrame($socket, 10); // 10 second timeout
    
    if ($response) {
        echo "5. Response received from Qlik Engine\n";
        echo "## Message received: " . $response . "\n";
        
        // Save to file
        if (file_put_contents('GetEngineInfo.txt', $response)) {
            echo "GetEngineInfo.txt saved successfully!\n";
        } else {
            echo "Error saving GetEngineInfo.txt\n";
        }
    } else {
        echo "No valid response received or timed out\n";
    }
    
    // Close the connection
    fclose($socket);
    echo "WebSocket connection closed!\n";
}

// Function to create a WebSocket frame (simplified)
function createWebSocketFrame($payload) {
    $payloadLength = strlen($payload);
    
    // Basic frame with FIN bit set and opcode = 1 (text frame)
    $frame = chr(0x81);
    
    // Payload length
    if ($payloadLength <= 125) {
        $frame .= chr($payloadLength);
    } elseif ($payloadLength <= 65535) {
        $frame .= chr(126) . pack('n', $payloadLength);
    } else {
        $frame .= chr(127) . pack('J', $payloadLength);
    }
    
    // Add the payload
    $frame .= $payload;
    
    return $frame;
}

// Function to read a WebSocket frame with timeout
function readWebSocketFrame($socket, $timeoutSeconds = 10) {
    $startTime = time();
    
    // Read the first two bytes (header)
    $header = '';
    $headerLength = 0;
    
    while ($headerLength < 2 && (time() - $startTime) < $timeoutSeconds) {
        $chunk = fread($socket, 2 - $headerLength);
        if ($chunk === false || $chunk === '') {
            $info = stream_get_meta_data($socket);
            if ($info['timed_out']) {
                echo "Socket timed out while reading frame header\n";
                return null;
            }
            usleep(100000); // Sleep 100ms to prevent CPU overuse
            continue;
        }
        
        $header .= $chunk;
        $headerLength = strlen($header);
    }
    
    if ($headerLength < 2) {
        echo "Failed to read complete frame header\n";
        return null;
    }
    
    // Parse the header
    $fin = (ord($header[0]) & 0x80) != 0;
    $opcode = ord($header[0]) & 0x0F;
    $masked = (ord($header[1]) & 0x80) != 0;
    $payloadLength = ord($header[1]) & 0x7F;
    
    // Handle extended payload length
    if ($payloadLength == 126) {
        $lengthBytes = fread($socket, 2);
        if ($lengthBytes === false || strlen($lengthBytes) < 2) {
            echo "Failed to read 16-bit payload length\n";
            return null;
        }
        $payloadLength = unpack('n', $lengthBytes)[1];
    } elseif ($payloadLength == 127) {
        $lengthBytes = fread($socket, 8);
        if ($lengthBytes === false || strlen($lengthBytes) < 8) {
            echo "Failed to read 64-bit payload length\n";
            return null;
        }
        $payloadLength = unpack('J', $lengthBytes)[1];
    }
    
    // Check if payload length is reasonable
    if ($payloadLength > 1048576) { // 1MB limit
        echo "Payload too large: $payloadLength bytes\n";
        return null;
    }
    
    // Read mask if present (usually not for server responses)
    $mask = '';
    if ($masked) {
        $mask = fread($socket, 4);
        if ($mask === false || strlen($mask) < 4) {
            echo "Failed to read mask\n";
            return null;
        }
    }
    
    // Read payload with timeout handling
    $payload = '';
    $remaining = $payloadLength;
    $startReadTime = time();
    
    while ($remaining > 0 && !feof($socket) && (time() - $startReadTime) < $timeoutSeconds) {
        $data = fread($socket, min($remaining, 8192)); // Read in chunks
        if ($data === false || $data === '') {
            $info = stream_get_meta_data($socket);
            if ($info['timed_out']) {
                echo "Socket timed out while reading frame payload\n";
                break;
            }
            usleep(100000); // Sleep 100ms
            continue;
        }
        
        $remaining -= strlen($data);
        $payload .= $data;
    }
    
    if (strlen($payload) < $payloadLength) {
        echo "Warning: Incomplete payload received\n";
    }
    
    // Unmask the payload if needed
    if ($masked && $mask && strlen($payload) > 0) {
        for ($i = 0; $i < strlen($payload); $i++) {
            $payload[$i] = $payload[$i] ^ $mask[$i % 4];
        }
    }
    
    return $payload;
}

// Run the connection
try {
    echo "Starting Qlik Sense Engine connection...\n";
    connectToQlikEngine();
    echo "Connection complete\n";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>