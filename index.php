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

// Function to read a specific message by ID
function readMessageById($socket, $expectedId, $timeoutSeconds = 30) {
    $startTime = time();
    
    while ((time() - $startTime) < $timeoutSeconds) {
        $response = readWebSocketFrame($socket, 5);
        if (!$response) {
            continue;
        }
        
        echo "Received message: " . $response . "\n";
        
        $data = json_decode($response, true);
        if ($data === null) {
            echo "Warning: Failed to parse JSON: " . json_last_error_msg() . "\n";
            continue;
        }
        
        // Check if this is an event/notification message (has 'method' property)
        if (isset($data['method'])) {
            echo "Received notification: " . $data['method'] . "\n";
            continue; // Skip notifications, keep waiting for our response
        }
        
        // Check if this is our expected response (has matching 'id')
        if (isset($data['id']) && $data['id'] === $expectedId) {
            return $response;
        }
    }
    
    echo "Timeout waiting for message ID: $expectedId\n";
    return null;
}

// Function to connect to specific app and retrieve hypercube data
function getQlikObjectData($appId, $objectId) {
    global $certPath;
    
    echo "0. Connecting to Qlik app: $appId\n";
    
    $host = 'localhost';
    $port = 4747;
    $path = '/app/' . $appId;
    
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
    
    // Set socket timeout
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
    
    echo "3. Connected to app! WebSocket handshake successful\n";
    
    // Step 1: First, we need to open the document
    $openDocRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'OpenDoc',
        'handle' => -1,
        'params' => [
            $appId // App ID is the document ID
        ]
    ]);
    
    // Send OpenDoc request
    fwrite($socket, createWebSocketFrame($openDocRequest));
    echo "4. Sent OpenDoc request for app: $appId\n";
    
    // Read first message (usually OnConnected notification)
    $initialResponse = readWebSocketFrame($socket, 10);
    if ($initialResponse) {
        echo "Initial connection message: " . $initialResponse . "\n";
        
        // Parse it to see if it's a notification
        $initialData = json_decode($initialResponse, true);
        if ($initialData && isset($initialData['method']) && $initialData['method'] === 'OnConnected') {
            echo "Received OnConnected notification\n";
            
            // Now read the actual OpenDoc response with our message ID
            $docResponse = readMessageById($socket, 1, 10);
        } else {
            // If it's not the OnConnected notification, it might be our actual response
            $docResponse = $initialResponse;
        }
    } else {
        die("Failed to get any response\n");
    }
    
    if (!$docResponse) {
        die("Failed to get document response\n");
    }
    
    // Debug: Print raw response
    echo "Raw document response: " . $docResponse . "\n";
    
    $docData = json_decode($docResponse, true);
    if ($docData === null) {
        die("Failed to parse document response JSON: " . json_last_error_msg() . "\n");
    }
    
    if (isset($docData['error'])) {
        die("Error opening document: " . json_encode($docData['error']) . "\n");
    }
    
    if (!isset($docData['result']) || !isset($docData['result']['qReturn']) || !isset($docData['result']['qReturn']['qHandle'])) {
        die("Unexpected document response format. Response: " . $docResponse . "\n");
    }
    
    $docHandle = $docData['result']['qReturn']['qHandle'];
    echo "5. Document opened with handle: $docHandle\n";
    
    // Step 2: Get the object using GetObject with the document handle
    $getObjectRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => 2,
        'method' => 'GetObject',
        'handle' => $docHandle, // Use the document handle here
        'params' => [
            $objectId
        ]
    ]);
    
    // Send GetObject request
    fwrite($socket, createWebSocketFrame($getObjectRequest));
    echo "6. Sent GetObject request for object: $objectId\n";
    
    // Read the actual object response with our message ID
    $objectResponse = readMessageById($socket, 2, 10);
    
    if (!$objectResponse) {
        die("Failed to get object response\n");
    }
    
    // Debug: Print raw response
    echo "Raw object response: " . $objectResponse . "\n";
    
    $objectData = json_decode($objectResponse, true);
    if ($objectData === null) {
        die("Failed to parse object response JSON: " . json_last_error_msg() . "\n");
    }
    
    if (isset($objectData['error'])) {
        die("Error getting object: " . json_encode($objectData['error']) . "\n");
    }
    
    if (!isset($objectData['result']) || !isset($objectData['result']['qReturn']) || !isset($objectData['result']['qReturn']['qHandle'])) {
        die("Unexpected response format. Response: " . $objectResponse . "\n");
    }
    
    echo "7. Received object handle\n";
    $objectHandle = $objectData['result']['qReturn']['qHandle'];
    
    // Step 2: Get hypercube data using the GetLayout method
    $getLayoutRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => 3,
        'method' => 'GetLayout',
        'handle' => $objectHandle,
        'params' => []
    ]);
    
    // Send GetLayout request
    fwrite($socket, createWebSocketFrame($getLayoutRequest));
    echo "6. Sent GetLayout request for object handle: $objectHandle\n";
    
    // Read the actual layout response with our message ID
    $layoutResponse = readMessageById($socket, 3, 10);
    if (!$layoutResponse) {
        die("Failed to get layout response\n");
    }
    
    // Debug: Print raw response
    echo "Raw layout response: " . $layoutResponse . "\n";
    
    $layoutData = json_decode($layoutResponse, true);
    if ($layoutData === null) {
        die("Failed to parse layout response JSON: " . json_last_error_msg() . "\n");
    }
    
    if (isset($layoutData['error'])) {
        die("Error getting layout: " . json_encode($layoutData['error']) . "\n");
    }
    
    if (!isset($layoutData['result']) || !isset($layoutData['result']['qLayout'])) {
        die("Unexpected layout response format. Response: " . $layoutResponse . "\n");
    }
    
    echo "7. Received layout data\n";
    
    // Step 3: Get the hypercube data
    // Check if the object has a hypercube
    if (isset($layoutData['result']['qLayout']['qHyperCube'])) {
        $hypercube = $layoutData['result']['qLayout']['qHyperCube'];
        
        // Get dimensions and measures
        $dimensions = $hypercube['qDimensionInfo'];
        $measures = $hypercube['qMeasureInfo'];
        
        echo "8. Found hypercube with " . count($dimensions) . " dimensions and " . count($measures) . " measures\n";
        
        // Get data page request
        $dataPageRequest = json_encode([
            'jsonrpc' => '2.0',
            'id' => 4,
            'method' => 'GetHyperCubeData',
            'handle' => $objectHandle,
            'params' => [
                '/qHyperCubeDef',
                [
                    [
                        'qTop' => 0,
                        'qLeft' => 0,
                        'qHeight' => 100, // Get up to 100 rows
                        'qWidth' => count($dimensions) + count($measures)
                    ]
                ]
            ]
        ]);
        
        // Send hypercube data request
        fwrite($socket, createWebSocketFrame($dataPageRequest));
        echo "9. Sent hypercube data request\n";
        
        // Read the actual data response with our message ID
        $dataResponse = readMessageById($socket, 4, 10);
        if (!$dataResponse) {
            die("Failed to get hypercube data response\n");
        }
        
        // Debug: Print raw response
        echo "Raw hypercube data response: " . $dataResponse . "\n";
        
        $hypercubeData = json_decode($dataResponse, true);
        if ($hypercubeData === null) {
            die("Failed to parse hypercube data response JSON: " . json_last_error_msg() . "\n");
        }
        
        if (isset($hypercubeData['error'])) {
            die("Error getting hypercube data: " . json_encode($hypercubeData['error']) . "\n");
        }
        
        if (!isset($hypercubeData['result']) || !isset($hypercubeData['result']['qDataPages']) || 
            !isset($hypercubeData['result']['qDataPages'][0]) || !isset($hypercubeData['result']['qDataPages'][0]['qMatrix'])) {
            die("Unexpected hypercube data response format. Response: " . $dataResponse . "\n");
        }
        
        echo "10. Received hypercube data\n";
        
        // Process the data
        $qMatrix = $hypercubeData['result']['qDataPages'][0]['qMatrix'];
        
        // Create formatted output with headers and data
        $result = [
            'headers' => [],
            'data' => []
        ];
        
        // Add dimension headers
        foreach ($dimensions as $dim) {
            $result['headers'][] = $dim['qFallbackTitle'];
        }
        
        // Add measure headers
        foreach ($measures as $measure) {
            $result['headers'][] = $measure['qFallbackTitle'];
        }
        
        // Add data rows
        foreach ($qMatrix as $row) {
            $dataRow = [];
            foreach ($row as $cell) {
                // Qlik returns numbers in qNum and text in qText
                $dataRow[] = isset($cell['qNum']) && $cell['qNum'] !== 'NaN' ? $cell['qNum'] : $cell['qText'];
            }
            $result['data'][] = $dataRow;
        }
        
        // Save formatted data to file
        $jsonResult = json_encode($result, JSON_PRETTY_PRINT);
        file_put_contents('hypercube_data.json', $jsonResult);
        
        echo "11. Data saved to hypercube_data.json\n";
        echo "Data preview: " . substr($jsonResult, 0, 200) . "...\n";
        
        // Close the connection
        fclose($socket);
        echo "12. WebSocket connection closed\n";
        
        return $result;
    } else {
        echo "No hypercube found in the object\n";
        fclose($socket);
        return null;
    }
}

// Run the connection
try {
    // Example: Connect to general API
    // echo "Starting Qlik Sense Engine connection...\n";
    // connectToQlikEngine();
    // echo "Connection complete\n";
    
    // Example: Get data from specific app and object
    echo "Starting Qlik Object Data retrieval...\n";
    $data = getQlikObjectData('1f8ebe62-f436-4a90-a878-510c022c3326', 'UQWGWCF');
    echo "Data retrieval complete\n";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>