<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Core-System laden
require_once __DIR__ . '/classes/SecureSession.php';
require_once __DIR__ . '/classes/CsrfProtection.php';
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/classes/Database.php';
require_once __DIR__ . '/classes/Router.php';
require_once __DIR__ . '/classes/Template.php';
require_once __DIR__ . '/classes/Auth.php';
require_once __DIR__ . '/classes/RequestValidator.php';

SecureSession::initializeEarly();

// Globale Instanzen erstellen
$database = new Database();
$template = new Template();
$auth     = new Auth($database);
$router   = new Router($database, $template, $auth);

// Nur GET-Validierung verwenden
$requestValidator = new RequestValidator('GET');

// route & action validieren
$requestValidator->validate('route', ['type'=> 'text','regex'=> '/^[a-z_-]+$/']);
$requestValidator->validate('action', ['type'=> 'text','regex'=> '/^[a-z_-]+$/']);

$requestValidator->ensureConsumed();
$clean  = $requestValidator->getClean();
$errors = $requestValidator->getErrors();

// Wenn Fehler vorhanden → sofort abbrechen mit HTML-Fehlerseite
if (!empty(array_filter($errors))) {
    http_response_code(400); // Bad Request
    echo "<!doctype html><html lang='de'><head>
            <meta charset='utf-8'>
            <title>Fehler</title>
            <style>
                body { font-family: system-ui, sans-serif; padding:40px; background:#fafafa; }
                .error-box { max-width:600px; margin:0 auto; background:#fff3f3; border:1px solid #e0b4b4; padding:20px; border-radius:8px; }
                h1 { color:#9f3a38; }
                ul { color:#9f3a38; }
            </style>
          </head><body>
          <div class='error-box'>
            <h1>Fehler bei der Anfrage</h1>
            <p>Folgende Probleme sind aufgetreten:</p>
            <ul>";
    foreach ($errors as $field => $msgs) {
        foreach ((array)$msgs as $msg) {
            echo "<li><strong>".htmlspecialchars($field).":</strong> ".htmlspecialchars($msg)."</li>";
        }
    }
    echo "  </ul>
          </div>
          </body></html>";
    exit;
}

// Fallback für direkte index.php Aufrufe
$route  = $clean['route']  ?? '';
$action = $clean['action'] ?? 'index';
if ($route === '') {
    $route = 'home';
}

// Router ausführen
$router->handleRequest($route, $action);
