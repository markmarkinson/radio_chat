<?php
// ============================================================================
// DATEI: config/config.php
// Angepasst für Single Database System
// ============================================================================

if (session_status() === PHP_SESSION_NONE) {
    SecureSession::initializeEarly();
}

// Datenbank-Konfiguration (Single Database)
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'webradio_system');  // Nur eine Datenbank
define('DB_CHARSET', 'utf8mb4');

// System-Konstanten
define('LICENSE', 'full');
define('LICENSE_ID', 'WR2025001');
define('LICENSE_ABK', 'wr');

// Benutzerrollen (angepasst an neue DB-Struktur)
define('GUEST', 1);
define('USER', 10);
define('MODERATOR', 50);
define('ADMIN', 90);
define('SUPERADMIN', 100);

// Tabellen-Namen (ohne Präfix, neue Struktur)
define('TBL_USERS', 'users');
define('TBL_ROLES', 'roles');
define('TBL_USER_ROLES', 'user_roles');
define('TBL_PERMISSIONS', 'permissions');
define('TBL_ROLE_PERMISSIONS', 'role_permissions');
define('TBL_MODULES', 'modules');
define('TBL_SETTINGS', 'settings');
define('TBL_LOGS', 'logs');
define('TBL_USER_SESSIONS', 'user_sessions');

// System-Pfade
define('BASE_PATH', __DIR__ . '/../');
define('TEMPLATE_PATH', BASE_PATH . 'templates/');
define('UPLOAD_PATH', BASE_PATH . 'uploads/');
define('LOG_PATH', BASE_PATH . 'logs/');

// URL-Basis
define('BASE_URL', 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']) . '/');

// Timezone
date_default_timezone_set('Europe/Berlin');
