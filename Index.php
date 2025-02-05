<?php
// public/auth.php
require_once __DIR__ . '/../vendor/autoload.php';
use App\Models\User;
use App\Lib\Auth;
use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Database Configuration (Simplified for a single file)
// *** IMPORTANT: Never commit database credentials to your code repository! ***
$host = $_ENV['DB_HOST'];       // e.g., 'localhost'
$dbname = $_ENV['DB_DATABASE'];   // e.g., 'sports_db'
$user = $_ENV['DB_USERNAME'];        // e.g., 'root'
$pass = $_ENV['DB_PASSWORD'];     // e.g., ''
$db = null;

try {
    $db = new PDO("mysql:host=$host;dbname=$dbname", $user, $pass);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['message' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// Helper Functions (Simplified for a single file)
function findUserByUsername($username, $db) {
    $stmt = $db->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->execute(['username' => $username]);
    $stmt->setFetchMode(PDO::FETCH_ASSOC);
    return $stmt->fetch();
}

function createUser($username, $password, $email, $db) {
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare("INSERT INTO users (username, password, email) VALUES (:username, :password, :email)");
    $stmt->execute([
        'username' => $username,
        'password' => $hashedPassword,
        'email' => $email
    ]);
    return $db->lastInsertId();
}

// Routing
$action = isset($_GET['action']) ? $_GET['action'] : null;

switch ($action) {
    case 'register':
        handleRegistration($db);
        break;
    case 'login':
        handleLogin($db);
        break;
    default:
        http_response_code(400);
        echo json_encode(['message' => 'Invalid action']);
}

function handleRegistration($db) {
    $data = json_decode(file_get_contents("php://input"));

    if (isset($data->username) && isset($data->password) && isset($data->email)) {
        $username = trim($data->username);
        $password = trim($data->password);
        $email = trim($data->email);

        if (empty($username) || empty($password) || empty($email)) {
            http_response_code(400);
            echo json_encode(['message' => 'Username, password, and email are required']);
            return;
        }

        if (findUserByUsername($username, $db)) {
            http_response_code(400);
            echo json_encode(['message' => 'Username already exists']);
            return;
        }

        // Add more robust email validation here
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['message' => 'Invalid email format']);
            return;
        }

        $userId = createUser($username, $password, $email, $db);

        if ($userId) {
            http_response_code(201);
            echo json_encode(['message' => 'User registered successfully', 'userId' => $userId]);
        } else {
            http_response_code(500);
            echo json_encode(['message' => 'Failed to register user']);
        }
    } else {
        http_response_code(400);
        echo json_encode(['message' => 'Username, password, and email are required in the request body']);
    }
}

function handleLogin($db) {
    $data = json_decode(file_get_contents("php://input"));

    if (isset($data->username) && isset($data->password)) {
        $username = trim($data->username);
        $password = trim($data->password);

        if (empty($username) || empty($password)) {
            http_response_code(400);
            echo json_encode(['message' => 'Username and password are required']);
            return;
        }

        $user = findUserByUsername($username, $db);

        if ($user && password_verify($password, $user['password'])) {
            // Start a session (you'll need to call session_start() at the beginning of other scripts where you need session access)
            session_start();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];  //If role column exist

            http_response_code(200);
            echo json_encode(['message' => 'Login successful', 'user' => ['id' => $user['id'], 'username' => $user['username'], 'role' => $user['role']]]);
        } else {
            http_response_code(401);
            echo json_encode(['message' => 'Invalid credentials']);
        }
    } else {
        http_response_code(400);
        echo json_encode(['message' => 'Username and password are required in the request body']);
    }
}
?>
