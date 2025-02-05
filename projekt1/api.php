<?php
error_reporting(E_ALL); // Enable all error reporting
ini_set('display_errors', 1); // Display errors for debugging
header('Content-Type: application/json');

// Database connection details
$dbservername = "localhost";
$dbusername = "maresm";
$dbpassword = "1234567";
$dbname = "maresm_users";

// Function to establish a connection to the database
function get_db_connection(){
    global $dbservername, $dbname, $dbusername, $dbpassword;
    try
    {
        $conn = new PDO("mysql:host=$dbservername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $conn;
    }
    catch (PDOException $e)
    {
        echo json_encode(["error" => "Connection failed: " . $e->getMessage()]);
        http_response_code(500);
        exit();
    }
}
// Function to veryfy session token
function verify_user_session($session_token) {
    // Database connection
    $conn = get_db_connection();

    // Check if session_token exists in accounts
    $stmt = $conn->prepare("SELECT id FROM accounts WHERE session_token = ?");
    $stmt->execute([$session_token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Return the user ID if found, otherwise return null
    return $user ? $user['id'] : null;
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for user login ███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'login') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (!isset($data['username']) || !isset($data['password'])) {
        echo json_encode(["error" => "Username and password are required"]);
        http_response_code(400);
        exit();
    }

    $username = $data['username'];
    $password = $data['password'];

    try {
        $conn = get_db_connection();
        $stmt = $conn->prepare("SELECT id, password_hash FROM accounts WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            echo json_encode(["error" => "User not found"]);
            http_response_code(404);
            exit();
        }

        // Verify the password using password_verify() against the stored hash
        if (!password_verify($password, $user['password_hash'])) {
            echo json_encode(["error" => "Invalid password"]);
            http_response_code(401);
            exit();
        }

        // Generate a new session token
        do {
            $session_token = bin2hex(random_bytes(16)); // Generate a random session token
            $stmt = $conn->prepare("SELECT id FROM accounts WHERE session_token = ?");
            $stmt->execute([$session_token]);
            $existing_user = $stmt->fetch(PDO::FETCH_ASSOC);
        } while ($existing_user);

        // Update the session token in the database
        $stmt = $conn->prepare("UPDATE accounts SET session_token = ? WHERE id = ?");
        $stmt->execute([$session_token, $user['id']]);

        // Return the session token to the user
        echo json_encode(["session_token" => $session_token]);
        http_response_code(200);
    } catch (PDOException $e) {
        echo json_encode(["error" => "Login failed: " . $e->getMessage()]);
        http_response_code(500);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for checking if there's a waiting message ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'check_message') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (!isset($data['session_token'])) {
        echo json_encode(["error" => "Session token is required"]);
        http_response_code(400);
        exit();
    }

    $session_token = $data['session_token'];

    try {
        $user_id = verify_user_session($session_token);

        if (!$user_id) {
            echo json_encode(["error" => "Invalid session token"]);
            http_response_code(401);
            exit();
        }

        $conn = get_db_connection();
        $stmt = $conn->prepare("SELECT has_message FROM waiting_message WHERE id = ?");
        $stmt->execute([$user_id]);
        $message_status = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$message_status) {
            echo json_encode(["error" => "No message status found"]);
            http_response_code(404);
            exit();
        }

        echo json_encode(["has_message" => $message_status['has_message']]);
        http_response_code(200);
    } catch (PDOException $e) {
        echo json_encode(["error" => "Database error: " . $e->getMessage()]);
        http_response_code(500);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for adding a new message █████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'add_message') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Start collecting logs
    $log = "Starting message addition...\n";

    if (!isset($data['session_token']) || !isset($data['message']) || !isset($data['server_id'])) {
        $log .= "Part 1: Missing session_token, message, or server_id.\n";
        echo json_encode(["error" => "Session token, message, and server_id are required", "log" => $log]);
        http_response_code(400);
        exit();
    }

    $session_token = $data['session_token'];
    $message = $data['message'];
    $server_id = $data['server_id'];
    $log .= "Part 1: Received session_token: {$session_token}, message: {$message}, server_id: {$server_id}\n";

    if (preg_match('/<script.*?/is', $message) || preg_match('/<\?php.*?/is', $message)) {
        $log .= "Part 1.1: Malicious script or PHP tag detected in message.\n";
        echo json_encode(["error" => "Malicious content detected", "log" => $log]);
        http_response_code(400);
        exit();
    }

    try {
        // Database connection
        $conn = get_db_connection();
        $log .= "Part 2: Database connection successful.\n";

        // Check if session_token exists in accounts
        $stmt = $conn->prepare("SELECT id FROM accounts WHERE session_token = ?");
        $stmt->execute([$session_token]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $log .= "Part 3: Session token validation complete.\n";

        if (!$user) {
            $log .= "Part 3.1: Invalid session token.\n";
            echo json_encode(["error" => "Invalid session token", "log" => $log]);
            http_response_code(401);
            exit();
        }

        $log .= "Part 3.2: User ID found: {$user['id']}.\n";

        // Fetch server information
        $stmt = $conn->prepare("SELECT user_list, last_id, data FROM server WHERE server_id = ?");
        $stmt->execute([$server_id]);
        $server = $stmt->fetch(PDO::FETCH_ASSOC);
        $log .= "Part 4: Server data fetched.\n";

        if (!$server) {
            $log .= "Part 4.1: Server not found.\n";
            echo json_encode(["error" => "Server not found", "log" => $log]);
            http_response_code(404);
            exit();
        }

        $log .= "Part 4.2: Server found. User list: {$server['user_list']}, Last ID: {$server['last_id']}.\n";

        // Decode user_list from LONGTEXT
        $user_list = trim($server['user_list'], '"');
        $user_list = json_decode($user_list, true);
        $log .= "Part 5: Decoded user list: " . implode(', ', $user_list) . "\n";

        // Check if the user is authorized to post in this server
        if (!$user_list || !in_array($user['id'], $user_list)) {
            $log .= "Part 5.1: User ID {$user['id']} is not authorized to post in server ID: {$server_id}.\n";
            echo json_encode(["error" => "User not authorized to post in this server", "log" => $log]);
            http_response_code(403);
            exit();
        }

        $log .= "Part 5.2: User is authorized to post.\n";

        // Part 5.3: Set has_message to 1 for every user in the server list


        // Part 5.3: Set has_message to 1 for every user in the server list
        foreach ($user_list as $id) {
            $stmt = $conn->prepare("INSERT INTO waiting_message (id, has_message) VALUES (?, 1) ON DUPLICATE KEY UPDATE has_message = 1");
            $stmt->execute([$id]);
            $log .= "Part 5.3: Set has_message to 1 for user ID: {$id} in waiting_message table.\n";
        }

        // Handle message IDs and message list
        $last_id = $server['last_id'];
        $new_message_id = $last_id + 1;

        // Create new message as a JSON object
        $new_message = json_encode([
            'id' => $new_message_id,
            'message' => $message,
            'user_id' => $user['id']
        ]);
        $log .= "Part 6: Created new message: {$new_message}\n";

        // Decode the existing message list and add the new message
        $message_list = json_decode($server['data'], true);
        if (!is_array($message_list)) {
            $message_list = []; // If data is empty or invalid, start with an empty array
        }

        $max_message_count = 50;
        $log .= "Part 7: Preparing to add new message to message list.\n";

        if (count($message_list) < $max_message_count) {
            // Add new message to message list
            $message_list[] = $new_message;
            $new_data = json_encode($message_list); // Re-encode the list as JSON
            $log .= "Part 7.1: Message list updated, new message added.\n";

            // Update the server data with the new message
            $stmt = $conn->prepare("UPDATE server SET data = ?, last_id = ? WHERE server_id = ?");
            $stmt->execute([$new_data, $new_message_id, $server_id]);
            $log .= "Part 7.2: Server data updated in database.\n";

            echo json_encode(["message" => "Message added successfully", "message_id" => $new_message_id, "log" => $log]);
            http_response_code(200);
        } else {
            // Move the oldest (first) message to server_old and add new message
            $stmt = $conn->prepare("SELECT old_messages FROM server_old WHERE server_id = ?");
            $stmt->execute([$server_id]);
            $server_old = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$server_old) {
                // If no old messages exist, create a new entry in server_old
                $old_messages = [];
            } else {
                $old_messages = json_decode($server_old['old_messages'], true);
            }

            // Move the first message (oldest) to server_old
            $old_messages[] = array_shift($message_list); // Remove and return the first message
            $stmt = $conn->prepare("INSERT INTO server_old (server_id, old_messages) VALUES (?, ?) ON DUPLICATE KEY UPDATE old_messages = ?");
            $stmt->execute([$server_id, json_encode($old_messages), json_encode($old_messages)]);
            $log .= "Part 8: Old message moved to server_old.\n";

            // Add new message to the list
            $message_list[] = $new_message;
            $new_data = json_encode($message_list); // Re-encode the list as JSON

            $log .= "Part 8.1: Old message removed, new message added to message list.\n";
            $log .= "Part 8.2: New data after update: " . substr($new_data, 0, 100) . "...\n";

            // Update the server data with the new message
            $stmt = $conn->prepare("UPDATE server SET data = ?, last_id = ? WHERE server_id = ?");
            $stmt->execute([$new_data, $new_message_id, $server_id]);

            $log .= "Part 8.3: Server data updated in database after old message removal.\n";

            echo json_encode(["message" => "Message added and old message moved to server_old", "message_id" => $new_message_id, "log" => $log]);
            http_response_code(200);
        }
    } catch (PDOException $e) {
        // Log the database error
        $log .= "Part 9: Database error occurred: " . $e->getMessage() . "\n";

        echo json_encode(["error" => "Database error: " . $e->getMessage(), "log" => $log]);
        http_response_code(500);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for retrieving messages ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'get_messages') {
    // Get the JSON input from the request body
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);

    // Return received input for debugging if needed
    if (!$data) {
        echo json_encode([
            "error" => "Invalid JSON received.",
            "received_data" => $input
        ]);
        return;
    }

    // Check if the required parameters are present in the JSON input
    if (isset($data['server_id']) && isset($data['offset']) && isset($data['amount']) && isset($data['session_token'])) {
        $server_id = $data['server_id'];
        $offset = $data['offset'];
        $amount = $data['amount'];
        $session_token = $data['session_token'];

        $pdo = get_db_connection();

        // Verify the session token and check if the user is authorized to read messages
        try {
            // Check if session_token exists in accounts
            $stmt = $pdo->prepare("SELECT id FROM accounts WHERE session_token = ?");
            $stmt->execute([$session_token]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                echo json_encode(["error" => "Invalid session token"]);
                http_response_code(401);
                return;
            }

            // Fetch server information
            $stmt = $pdo->prepare("SELECT user_list FROM server WHERE server_id = ?");
            $stmt->execute([$server_id]);
            $server = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$server) {
                echo json_encode(["error" => "Server not found"]);
                http_response_code(404);
                return;
            }


            // Decode user_list from LONGTEXT
            $user_list = trim($server['user_list'], '"');
            $user_list = json_decode($user_list, true);

            // Check if the user is authorized to read messages from this server
            if (!$user_list || !in_array($user['id'], $user_list)) {
                echo json_encode(["error" => "User not authorized to read from this server"]);
                http_response_code(403);
                return;
            }

            $id = $user['id'];

            // Part X: Switch off has_message to 0 for the user when the message is checked
            $stmt = $pdo->prepare("UPDATE waiting_message SET has_message = 0 WHERE id = ?");
            $stmt->execute([$id]);


            // If the user is authorized, proceed to fetch messages
            $message_count = 50; // Hardcoded message count for testing
            $messages = [];

            if ($offset + $amount <= $message_count) {
                // Query the `server` (most recent messages first)
                $query_server = "SELECT data FROM server WHERE server_id = :server_id";
                $stmt_server = $pdo->prepare($query_server);
                $stmt_server->bindParam(':server_id', $server_id, PDO::PARAM_INT);
                $stmt_server->execute();
                $server_data = $stmt_server->fetch(PDO::FETCH_ASSOC);

                if (!$server_data) {
                    echo json_encode(["error" => "No data found for server_id: " . $server_id]);
                    return;
                }

                // Decode the LONGTEXT data (most recent first)
                $decoded_messages = json_decode($server_data['data'], true);

                // Check for JSON decode errors
                if (json_last_error() !== JSON_ERROR_NONE) {
                    echo json_encode([
                        "error" => "JSON decode error in server data: " . json_last_error_msg(),
                        "raw_data" => $server_data['data'],
                        "section" => "server decoding"
                    ]);
                    return;
                }

                // Reverse the array so the last messages are first
                $decoded_messages = array_reverse($decoded_messages);

                // Slice the messages based on the offset and amount
                $messages = array_slice($decoded_messages, $offset, $amount);

            } else {
                // Query both `server` and `server_old` for more messages
                $messages = [];

                // Query `server` (most recent messages first)
                $query_server = "SELECT data FROM server WHERE server_id = :server_id";
                $stmt_server = $pdo->prepare($query_server);
                $stmt_server->bindParam(':server_id', $server_id, PDO::PARAM_INT);
                $stmt_server->execute();
                $server_data = $stmt_server->fetch(PDO::FETCH_ASSOC);

                if (!$server_data) {
                    echo json_encode(["error" => "No data found for server_id: " . $server_id]);
                    return;
                }

                // Decode the data (most recent first)
                $decoded_messages = json_decode($server_data['data'], true);

                if (json_last_error() !== JSON_ERROR_NONE) {
                    echo json_encode([
                        "error" => "JSON decode error in server data: " . json_last_error_msg(),
                        "raw_data" => $server_data['data'],
                        "section" => "server decoding"
                    ]);
                    return;
                }

                // Reverse the array so the last messages are first
                $decoded_messages = array_reverse($decoded_messages);

                // Add the messages from `server`
                $messages = array_merge($messages, $decoded_messages);

                // Query `server_old` if more messages are needed
                $needed_from_old = ($offset + $amount) - count($messages);
                $query_server_old = "SELECT old_messages FROM server_old WHERE server_id = :server_id LIMIT :needed_from_old";
                $stmt_server_old = $pdo->prepare($query_server_old);
                $stmt_server_old->bindParam(':server_id', $server_id, PDO::PARAM_INT);
                $stmt_server_old->bindParam(':needed_from_old', $needed_from_old, PDO::PARAM_INT);
                $stmt_server_old->execute();
                $server_old_messages  = $stmt_server_old->fetch(PDO::FETCH_ASSOC);

                if (!$server_old_messages ) {
                    echo json_encode([
                        "error" => "No old data found for server_id: " . $server_id,
                        "section" => "server_old query"
                    ]);
                    return;
                }

                // Decode old messages (most recent first)
                $decoded_old_messages = json_decode($server_old_messages ['old_messages'], true);

                if (json_last_error() !== JSON_ERROR_NONE) {
                    echo json_encode([
                        "error" => "JSON decode error in old server data: " . json_last_error_msg(),
                        "raw_old_messages " => $server_old_messages ['old_messages'],
                        "section" => "server_old decoding"
                    ]);
                    return;
                }

                // Reverse the old messages and merge
                $decoded_old_messages = array_reverse($decoded_old_messages);
                $messages = array_merge($messages, $decoded_old_messages);

                // Slice the messages based on the offset and amount
                $messages = array_slice($messages, $offset, $amount);
            }

            // Return the messages as JSON
            echo json_encode($messages);

        } catch (PDOException $e) {
            echo json_encode(["error" => "Database query failed: " . $e->getMessage()]);
            return;
        }
    } else {
        // Return error message with details about missing parameters
        $missing_params = [];
        if (!isset($data['server_id'])) $missing_params[] = 'server_id';
        if (!isset($data['offset'])) $missing_params[] = 'offset';
        if (!isset($data['amount'])) $missing_params[] = 'amount';
        if (!isset($data['session_token'])) $missing_params[] = 'session_token';

        echo json_encode([
            "error" => "Missing parameters: " . implode(", ", $missing_params),
            "received_data" => $data
        ]);
        return;
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for getting username █████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['user_id'])) {
    $user_id = $_GET['user_id'];

    try
    {
        $conn = get_db_connection();
        $stmt = $conn->prepare("SELECT username FROM accounts WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            echo json_encode(["username" => $user['username']]);
            http_response_code(200);
        } else {
            echo json_encode(["error" => "User not found"]);
            http_response_code(404);
        }
    }
    catch (PDOException $e)
    {
        echo json_encode(["error" => "Query failed: " . $e->getMessage()]);
        http_response_code(500);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for queriing the server name by server_id ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'get_server_name') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if server_id is provided
    if (!isset($data['server_id'])) {
        echo json_encode(["error" => "server_id is required"]);
        http_response_code(400);
        exit();
    }

    $server_id = $data['server_id'];

    try {
        // Database connection
        $conn = get_db_connection();

        // Query server name by server_id
        $stmt = $conn->prepare("SELECT name FROM server WHERE server_id = ?");
        $stmt->execute([$server_id]);
        $server = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$server) {
            echo json_encode(["error" => "Server not found"]);
            http_response_code(404);
            exit();
        }

        // Return the server name
        echo json_encode(["server_name" => $server['name']]);
        http_response_code(200);
    } catch (PDOException $e) {
        echo json_encode(["error" => "Database error: " . $e->getMessage()]);
        http_response_code(500);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for loging out ███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'logout') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if session_token is provided
    if (!isset($data['session_token'])) {
        echo json_encode(["error" => "session_token is required"]);
        http_response_code(400);
        exit();
    }

    $session_token = $data['session_token'];

    // Database connection
    $conn = get_db_connection();

    // Verify the session token
    $user_id = verify_user_session($session_token);
    

    if ($user_id)
    {
        // Generate a new random token and ensure it is unique
        do {
            $new_token = bin2hex(random_bytes(16)); // Generate a 32-character random token
            $stmt = $conn->prepare("SELECT id FROM accounts WHERE session_token = ?");
            $stmt->execute([$new_token]);
        } while ($stmt->fetch(PDO::FETCH_ASSOC)); // Check if the token exists

        // Update the session token in the database
        $stmt = $conn->prepare("UPDATE accounts SET session_token = ? WHERE id = ?");
        $stmt->execute([$new_token, $user_id]);

        // Return success response
        echo json_encode(["message" => "User logged out successfully", "new_token" => $new_token]);
        http_response_code(200);
    } else {
        echo json_encode(["error" => "Invalid session token"]);
        http_response_code(401);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for getting servers user is in ███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'get_servers') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if session_token is provided
    if (!isset($data['session_token'])) {
        echo json_encode(["error" => "session_token is required"]);
        http_response_code(400);
        exit();
    }

    $session_token = $data['session_token'];

    // Database connection using PDO
    $conn = get_db_connection();

    // Verify the session token
    $user_id = verify_user_session($session_token);
    if ($user_id === false) {
        echo json_encode(["error" => "Invalid session token"]);
        http_response_code(401);
        exit();
    }

    // Query the `waiting_message` table to get the servers associated with the user_id
    $stmt = $conn->prepare("SELECT servers FROM waiting_message WHERE id = ?");
    $stmt->execute([$user_id]);

    // Check if any servers are found
    $servers = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($servers) {
        // Return the servers as raw strings, wrapped in JSON
        $server_data = [];
        foreach ($servers as $row) {
            $server_data[] = $row['servers'];  // No processing, just return the string as is
        }

        echo json_encode(["servers" => $server_data]);
    } else {
        echo json_encode(["error" => "No servers found for this user"]);
    }

    $conn = null; // Close the connection
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for changing servers user is in  █████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'change_servers') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if session_token and new_servers are provided
    if (!isset($data['session_token']) || !isset($data['new_servers'])) {
        echo json_encode(["error" => "session_token and new_servers are required"]);
        http_response_code(400);
        exit();
    }

    $session_token = $data['session_token'];
    $new_servers = $data['new_servers'];  // This is not JSON, assuming your own format

    // Database connection using PDO
    $conn = get_db_connection();

    // Verify the session token
    $user_id = verify_user_session($session_token);
    if ($user_id === false) {
        echo json_encode(["error" => "Invalid session token"]);
        http_response_code(401);
        exit();
    }

    // Update the waiting_message table with the new server data
    $stmt = $conn->prepare("UPDATE waiting_message SET servers = ? WHERE id = ?");
    $stmt->execute([$new_servers, $user_id]);

    // Check if the update was successful
    if ($stmt->rowCount() > 0) {
        echo json_encode(["success" => true, "new_servers" => $new_servers]);
    } else {
        echo json_encode(["error" => "Failed to update servers or no changes made"]);
        http_response_code(500);
    }

    $conn = null;  // Close the connection
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for geting user id ███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'get_user_id') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if session_token is provided
    if (!isset($data['session_token'])) {
        echo json_encode(["error" => "session_token is required"]);
        http_response_code(400);
        exit();
    }

    $session_token = $data['session_token'];

    // Database connection
    $conn = get_db_connection();

    // Verify the session token and retrieve the user ID
    $user_id = verify_user_session($session_token);

    if ($user_id) {
        // Return the user ID as part of the response
        echo json_encode(["user_id" => $user_id]);
        http_response_code(200);
    } else {
        echo json_encode(["error" => "Invalid session token"]);
        http_response_code(401);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for changing username ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'change_username') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if session_token and new_username are provided
    if (!isset($data['session_token']) || !isset($data['new_username'])) {
        echo json_encode(["error" => "session_token and new_username are required"]);
        http_response_code(400);
        exit();
    }

    $session_token = $data['session_token'];
    $new_username = $data['new_username'];

    // Database connection
    $conn = get_db_connection();

    // Verify the session token
    $user_id = verify_user_session($session_token);

    if ($user_id) {
        // Check if the new username is already taken
        $stmt = $conn->prepare("SELECT id FROM accounts WHERE username = ?");
        $stmt->execute([$new_username]);

        if ($stmt->fetch(PDO::FETCH_ASSOC)) {
            echo json_encode(["error" => "Username already taken"]);
            http_response_code(409); // Conflict
            exit();
        }

        // Update the username in the database
        $stmt = $conn->prepare("UPDATE accounts SET username = ? WHERE id = ?");
        $stmt->execute([$new_username, $user_id]);

        // Return success response
        echo json_encode(["message" => "Username updated successfully"]);
        http_response_code(200);
    } else {
        echo json_encode(["error" => "Invalid session token"]);
        http_response_code(401);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for changing password ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'change_password') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if session_token, current_password, and new_password are provided
    if (!isset($data['session_token']) || !isset($data['current_password']) || !isset($data['new_password'])) {
        echo json_encode(["error" => "session_token, current_password, and new_password are required"]);
        http_response_code(400);
        exit();
    }

    $session_token = $data['session_token'];
    $current_password = $data['current_password'];
    $new_password = $data['new_password'];

    // Database connection
    $conn = get_db_connection();

    // Verify the session token
    $user_id = verify_user_session($session_token);

    if ($user_id) {
        // Fetch the current password hash from the database
        $stmt = $conn->prepare("SELECT password_hash FROM accounts WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Verify the current password using password_verify() to compare the hashed password
        if (!password_verify($current_password, $user['password_hash'])) {
            echo json_encode(["error" => "Current password is incorrect"]);
            http_response_code(403); // Forbidden
            exit();
        }

        // Hash the new password securely using password_hash()
        $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);

        // Update the password in the database with the new hashed password
        $stmt = $conn->prepare("UPDATE accounts SET password_hash = ? WHERE id = ?");
        $stmt->execute([$new_password_hash, $user_id]);

        // Return success response
        echo json_encode(["message" => "Password updated successfully"]);
        http_response_code(200);
    } else {
        echo json_encode(["error" => "Invalid session token"]);
        http_response_code(401);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API  for creating user ███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'create_user') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if session_token is provided
    if (!isset($data['session_token'])) {
        echo json_encode(["error" => "session_token is required"]);
        http_response_code(400);
        exit();
    }

    $session_token = $data['session_token'];

    // Validate if all required user data is provided
    if (!isset($data['username']) || !isset($data['password'])) {
        echo json_encode(["error" => "username and password are required"]);
        http_response_code(400);
        exit();
    }

    $username = $data['username'];
    $password = $data['password'];

    // Database connection
    $conn = get_db_connection();

    // Verify the session token to get the creator's user ID
    $creator_id = verify_user_session($session_token);

    if ($creator_id) {
        // Check if the username already exists
        $stmt = $conn->prepare("SELECT id FROM accounts WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch(PDO::FETCH_ASSOC)) {
            echo json_encode(["error" => "Username already exists"]);
            http_response_code(400);
            exit();
        }

        // Generate a random session token for the new user
        do {
            $new_token = bin2hex(random_bytes(16)); // Generate a 32-character random token
            $stmt = $conn->prepare("SELECT id FROM accounts WHERE session_token = ?");
            $stmt->execute([$new_token]);
        } while ($stmt->fetch(PDO::FETCH_ASSOC)); // Check if the token exists

        // Hash the password
        $password_hash = password_hash($password, PASSWORD_DEFAULT);

        // Insert the new user into the database
        $stmt = $conn->prepare("INSERT INTO accounts (username, password_hash, session_token, created_at, creator_id) VALUES (?, ?, ?, NOW(), ?)");
        $stmt->execute([$username, $password_hash, $new_token, $creator_id]);

        // Return success response
        echo json_encode([
            "message" => "User created successfully",
            "username" => $username,
            "new_token" => $new_token
        ]);
        http_response_code(201);
    } else {
        echo json_encode(["error" => "Invalid session token"]);
        http_response_code(401);
    }
}
// ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
// API for creating server ██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_GET['action']) && $_GET['action'] == 'create_server') {
    $data = json_decode(file_get_contents('php://input'), true);

    // Start collecting logs
    $log = "Starting server creation...\n";

    // Use the supplied database connection
    $conn = get_db_connection();

    // Check if session_token, name, and user_list are passed
    if (!isset($data['session_token']) || !isset($data['name']) || !isset($data['user_list'])) {
        $log .= "Part 1: Missing session_token, name, or user_list.\n";
        echo json_encode(["error" => "Session token, name, and user list are required", "log" => $log]);
        http_response_code(400);
        exit();
    }

    // Assign values
    $session_token = $data['session_token'];
    $name = $data['name'];
    $user_list = $data['user_list'];  // This will be passed as a string (e.g., "[1,2,3]")
    $log .= "Part 1: Received session_token: {$session_token}, name: {$name}, user_list: {$user_list}\n";

    // Verify user session
    $creator_id = verify_user_session($session_token);  // Ensure this function returns the creator's user ID
    if (!$creator_id) {
        $log .= "Error: Invalid session token.\n";
        echo json_encode(["error" => "Invalid session token", "log" => $log]);
        http_response_code(401);
        exit();
    }

    try {
        // Query for the latest server ID to increment it
        $log .= "Part 2: Querying the last server ID.\n";
        $query = "SELECT MAX(server_id) as last_server_id FROM `server`";
        $stmt = $conn->prepare($query);
        $stmt->execute();
        $last_server_id = $stmt->fetch(PDO::FETCH_ASSOC)['last_server_id'];

        // Generate new server_id by incrementing the last one or create a new one if empty
        $server_id = $last_server_id ? (int)$last_server_id + 1 : 1; // If no previous server, start from 1

        // Generate dynamic data
        $last_id = 0;
        $data_field = '[]';  // Initial empty data for messages
        $old_messages = '[]';  // Initial empty data for old messages

        // Insert into `server` table using the existing connection
        $log .= "Part 3: Preparing to insert into `server` table.\n";
        $insert_server_sql = "INSERT INTO `server` (server_id, name, last_id, user_list, data, creator_id) 
                              VALUES (:server_id, :name, :last_id, :user_list, :data, :creator_id)";
        $stmt = $conn->prepare($insert_server_sql);
        $stmt->execute([
            ':server_id' => $server_id,
            ':name' => $name,
            ':last_id' => $last_id,
            ':user_list' => $user_list,  // Pass the user list as a string
            ':data' => $data_field,
            ':creator_id' => $creator_id  // Save the creator's ID
        ]);

        $log .= "Part 4: Inserted into `server` table.\n";

        // Insert into `server_old` table
        $log .= "Part 5: Preparing to insert into `server_old` table.\n";
        $insert_server_old_sql = "INSERT INTO `server_old` (server_id, old_messages ) 
                                  VALUES (:server_id, :old_messages)";
        $stmt = $conn->prepare($insert_server_old_sql);
        $stmt->execute([
            ':server_id' => $server_id,
            ':old_messages' => $old_messages  // Fixed the extra space here
        ]);
        
        $log .= "Part 6: Inserted into `server_old` table.\n";

        // Success response with server_id
        echo json_encode([
            "success" => true, 
            "server_id" => $server_id, 
            "log" => $log
        ]);
        http_response_code(200);

    } catch (Exception $e) {
        // Log and handle errors
        $log .= "Error: " . $e->getMessage() . "\n";
        echo json_encode(["error" => "Database error", "log" => $log]);
        http_response_code(500);
    }
}

?>