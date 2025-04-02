<?php
/**
 * Simple Qlik Sense Engine API Connection in PHP
 * This script connects to the Qlik Sense Engine API using a custom WebSocket implementation
 */

// Increase execution time limit for long-running connections
set_time_limit(120); // 2 minutes

// Error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set certificate path
$certPath = __DIR__ . '/certs';

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

// Function to connect to app and get a WebSocket session
function connectToQlikApp($appId) {
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
        "X-Qlik-User: UserDirectory=ALEX-PC; UserId=lenovo"
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
    
    // Handle initial connection notification
    $initialResponse = readWebSocketFrame($socket, 10);
    if ($initialResponse) {
        echo "Initial connection message: " . $initialResponse . "\n";
    }
    
    // Step 1: Open the Document
    $openDocRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'OpenDoc',
        'handle' => -1,
        'params' => [
            $appId
        ]
    ]);
    
    // Send OpenDoc request
    fwrite($socket, createWebSocketFrame($openDocRequest));
    echo "4. Sent OpenDoc request for app: $appId\n";
    
    // Read the document response
    $docResponse = readMessageById($socket, 1, 10);
    if (!$docResponse) {
        die("Failed to get document response\n");
    }
    
    $docData = json_decode($docResponse, true);
    if (isset($docData['error'])) {
        die("Error opening document: " . json_encode($docData['error']) . "\n");
    }
    
    $docHandle = $docData['result']['qReturn']['qHandle'];
    echo "5. Document opened with handle: $docHandle\n";
    
    // Return the socket and doc handle for further operations
    return [
        'socket' => $socket,
        'docHandle' => $docHandle,
        'messageId' => 2 // Next message ID to use
    ];
}

// Function to select a field value using an existing session
function selectFieldValue($session, $fieldName, $fieldValue) {
    $socket = $session['socket'];
    $docHandle = $session['docHandle'];
    $messageId = $session['messageId'];
    
    echo "Starting field selection for $fieldName = $fieldValue\n";
    
    // Step 1: Create a session object for field selection
    $createSessionObjectRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => $messageId,
        'method' => 'CreateSessionObject',
        'handle' => $docHandle,
        'params' => [
            [
                'qInfo' => [
                    'qType' => 'ListObject',
                    'qId' => ''
                ],
                'qListObjectDef' => [
                    'qDef' => [
                        'qFieldDefs' => [
                            $fieldName
                        ]
                    ],
                    'qInitialDataFetch' => [
                        [
                            'qTop' => 0,
                            'qLeft' => 0,
                            'qHeight' => 100,
                            'qWidth' => 1
                        ]
                    ]
                ]
            ]
        ]
    ]);
    
    // Send CreateSessionObject request
    fwrite($socket, createWebSocketFrame($createSessionObjectRequest));
    echo "6. Sent CreateSessionObject request for field: $fieldName\n";
    
    // Read the session object response
    $sessionResponse = readMessageById($socket, $messageId, 10);
    $messageId++;
    
    if (!$sessionResponse) {
        die("Failed to get session object response\n");
    }
    
    $sessionData = json_decode($sessionResponse, true);
    if (isset($sessionData['error'])) {
        die("Error creating session object: " . json_encode($sessionData['error']) . "\n");
    }
    
    $listObjectHandle = $sessionData['result']['qReturn']['qHandle'];
    echo "7. Created list object with handle: $listObjectHandle\n";
    
    // Step 2: Get the layout to find the values
    $getLayoutRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => $messageId,
        'method' => 'GetLayout',
        'handle' => $listObjectHandle,
        'params' => []
    ]);
    
    // Send GetLayout request
    fwrite($socket, createWebSocketFrame($getLayoutRequest));
    echo "8. Sent GetLayout request for list object\n";
    
    // Read the layout response
    $layoutResponse = readMessageById($socket, $messageId, 10);
    $messageId++;
    
    if (!$layoutResponse) {
        die("Failed to get layout\n");
    }
    
    $layoutData = json_decode($layoutResponse, true);
    if (isset($layoutData['error'])) {
        die("Error getting layout: " . json_encode($layoutData['error']) . "\n");
    }
    
    // Get the qMatrix which contains the field values
    if (!isset($layoutData['result']['qLayout']['qListObject']['qDataPages'][0]['qMatrix'])) {
        die("Unexpected layout format\n");
    }
    
    $matrix = $layoutData['result']['qLayout']['qListObject']['qDataPages'][0]['qMatrix'];
    echo "9. Retrieved list of values for field: $fieldName\n";
    
    // Find the element number of our target value
    $elementNumber = null;
    foreach ($matrix as $row) {
        if (isset($row[0]['qText']) && $row[0]['qText'] === $fieldValue) {
            $elementNumber = $row[0]['qElemNumber'];
            break;
        }
    }
    
    if ($elementNumber === null) {
        die("Value '$fieldValue' not found in field '$fieldName'\n");
    }
    
    echo "10. Found value '$fieldValue' with element number: $elementNumber\n";
    
    // Step 3: Select the value using the element number
    $selectValuesRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => $messageId,
        'method' => 'SelectListObjectValues',
        'handle' => $listObjectHandle,
        'params' => [
            '/qListObjectDef',
            [$elementNumber],  // Element numbers to select
            false  // Toggle selection mode (false = replace current selection)
        ]
    ]);
    
    // Send SelectValues request
    fwrite($socket, createWebSocketFrame($selectValuesRequest));
    echo "11. Sent select request for value: $fieldValue (element: $elementNumber)\n";
    
    // Read the select response
    $selectResponse = readMessageById($socket, $messageId, 10);
    $messageId++;
    
    if (!$selectResponse) {
        die("Failed to get selection response\n");
    }
    
    $selectData = json_decode($selectResponse, true);
    if (isset($selectData['error'])) {
        die("Error selecting value: " . json_encode($selectData['error']) . "\n");
    }
    
    echo "12. Value '$fieldValue' selected in field '$fieldName'\n";
    
    // Step 4: Verify that the selection was applied using GetField method instead
    $getFieldRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => $messageId,
        'method' => 'GetField',
        'handle' => $docHandle,
        'params' => [
            $fieldName
        ]
    ]);
    
    // Send GetField request
    fwrite($socket, createWebSocketFrame($getFieldRequest));
    echo "13. Sent GetField request to verify selection state\n";
    
    // Read the response
    $fieldResponse = readMessageById($socket, $messageId, 10);
    $messageId++;
    
    if (!$fieldResponse) {
        die("Failed to get field response\n");
    }
    
    $fieldData = json_decode($fieldResponse, true);
    if (isset($fieldData['error'])) {
        die("Error getting field: " . json_encode($fieldData['error']) . "\n");
    }
    
    $fieldHandle = $fieldData['result']['qReturn']['qHandle'];
    echo "14. Got field handle: $fieldHandle\n";
    
    // Get field description
    $getFieldDescRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => $messageId,
        'method' => 'GetNxProperties',
        'handle' => $fieldHandle,
        'params' => []
    ]);
    
    // Send GetNxProperties request
    fwrite($socket, createWebSocketFrame($getFieldDescRequest));
    echo "15. Sent GetNxProperties request for field properties\n";
    
    // Read the response
    $fieldPropsResponse = readMessageById($socket, $messageId, 10);
    $messageId++;
    
    if (!$fieldPropsResponse) {
        die("Failed to get field properties\n");
    }
    
    $fieldProps = json_decode($fieldPropsResponse, true);
    if (isset($fieldProps['error'])) {
        echo "Warning: Error getting field properties: " . json_encode($fieldProps['error']) . "\n";
    } else {
        echo "16. Got field properties, selection state verified\n";
    }
    
    // One more final check - use GetSelectedValues to double-check
    $getSelectedRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => $messageId,
        'method' => 'GetLayout',
        'handle' => $listObjectHandle,
        'params' => []
    ]);
    
    // Send GetLayout request to check selected values
    fwrite($socket, createWebSocketFrame($getSelectedRequest));
    echo "17. Sent GetLayout request to check selected values\n";
    
    // Read the response
    $selectedResponse = readMessageById($socket, $messageId, 10);
    $messageId++;
    
    if (!$selectedResponse) {
        die("Failed to get selected values\n");
    }
    
    $selectedData = json_decode($selectedResponse, true);
    if (isset($selectedData['error'])) {
        echo "Warning: Error getting selected values: " . json_encode($selectedData['error']) . "\n";
    } else {
        if (isset($selectedData['result']['qLayout']['qListObject']['qSelectionInfo']['qInSelections'])) {
            $inSelections = $selectedData['result']['qLayout']['qListObject']['qSelectionInfo']['qInSelections'];
            echo "18. Selection active status: " . ($inSelections ? "True" : "False") . "\n";
        } else {
            echo "18. Could not determine selection status from response\n";
        }
    }
    
    // Return the updated session with the new message ID
    return [
        'socket' => $socket,
        'docHandle' => $docHandle,
        'messageId' => $messageId
    ];
}

// Function to get hypercube data using an existing session
function getQlikObjectData($session, $objectId) {
    $socket = $session['socket'];
    $docHandle = $session['docHandle'];
    $messageId = $session['messageId'];
    
    echo "Starting object data retrieval for object: $objectId\n";
    
    // Step 1: Get the object using GetObject with the document handle
    $getObjectRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => $messageId,
        'method' => 'GetObject',
        'handle' => $docHandle,
        'params' => [
            $objectId
        ]
    ]);
    
    // Send GetObject request
    fwrite($socket, createWebSocketFrame($getObjectRequest));
    echo "13. Sent GetObject request for object: $objectId\n";
    
    // Read the object response
    $objectResponse = readMessageById($socket, $messageId, 10);
    $messageId++;
    
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
    
    echo "14. Received object handle\n";
    $objectHandle = $objectData['result']['qReturn']['qHandle'];
    
    // Step 2: Get hypercube data using the GetLayout method
    $getLayoutRequest = json_encode([
        'jsonrpc' => '2.0',
        'id' => $messageId,
        'method' => 'GetLayout',
        'handle' => $objectHandle,
        'params' => []
    ]);
    
    // Send GetLayout request
    fwrite($socket, createWebSocketFrame($getLayoutRequest));
    echo "15. Sent GetLayout request for object handle: $objectHandle\n";
    
    // Read the layout response
    $layoutResponse = readMessageById($socket, $messageId, 10);
    $messageId++;
    
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
    
    echo "16. Received layout data\n";
    
    // Step 3: Get the hypercube data
    // Check if the object has a hypercube
    if (isset($layoutData['result']['qLayout']['qHyperCube'])) {
        $hypercube = $layoutData['result']['qLayout']['qHyperCube'];
        
        // Get dimensions and measures
        $dimensions = $hypercube['qDimensionInfo'];
        $measures = $hypercube['qMeasureInfo'];
        
        echo "17. Found hypercube with " . count($dimensions) . " dimensions and " . count($measures) . " measures\n";
        
        // Get data page request
        $dataPageRequest = json_encode([
            'jsonrpc' => '2.0',
            'id' => $messageId,
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
        echo "18. Sent hypercube data request\n";
        
        // Read the data response
        $dataResponse = readMessageById($socket, $messageId, 10);
        $messageId++;
        
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
        
        echo "19. Received hypercube data\n";
        
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
        
        echo "20. Data saved to hypercube_data.json\n";
        echo "Data preview: " . substr($jsonResult, 0, 200) . "...\n";
        
        // Return the result data and updated session
        return [
            'data' => $result,
            'session' => [
                'socket' => $socket,
                'docHandle' => $docHandle,
                'messageId' => $messageId
            ]
        ];
    } else {
        echo "No hypercube found in the object\n";
        return [
            'data' => null,
            'session' => [
                'socket' => $socket,
                'docHandle' => $docHandle,
                'messageId' => $messageId
            ]
        ];
    }
}

// Function to close a Qlik session
function closeQlikSession($session) {
    if (isset($session['socket']) && is_resource($session['socket'])) {
        fclose($session['socket']);
        echo "Qlik session closed\n";
    }
}

// Run the connection
try {
    // 1. Connect and get session
    echo "Starting Qlik Sense connection...\n";
    $session = connectToQlikApp('1f8ebe62-f436-4a90-a878-510c022c3326');
    
    // 2. Select the field value
    //echo "Performing field selection...\n";
    //$session = selectFieldValue($session, 'DEPARTMENT', 'Ladies Bag');
    $session = selectFieldValue($session, 'Store Name', 'Camarillo Premium Outlets');
    
    // 3. Get the object data
    echo "Retrieving object data...\n";
    $result = getQlikObjectData($session, 'UQWGWCF');
    $data = $result['data'];
    $session = $result['session'];
    
    // 4. Close the session
    closeQlikSession($session);
    
    echo "All operations completed successfully\n";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>