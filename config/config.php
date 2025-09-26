<?php
// Datenbank-Konfiguration
define('DB_HOST', 'localhost');
define('DB_USER', 'webradio_user');
define('DB_PASS', 'your_password');
define('DB_NAME_MAIN', 'webradio_main');       // Database 0
define('DB_NAME_RADIO', 'webradio_radio');     // Database 1
define('DB_CHARSET', 'utf8mb4');

// System-Konstanten
define('LICENSE', 'full');                      // full, standard, trial
define('LICENSE_ID', 'WR2025001');
define('LICENSE_ABK', 'wr');

// Benutzerklassen
define('USER', 1);
define('MITGLIED', 2);
define('MODERATOR', 3);
define('ADMINSTATOR', 4);
define('SUPERADMIN', 5);
define('WEBMASTER', 6);
define('INHABER', 7);

// Tabellen-Präfixe
define('DB_PREFIX', 'wr_');
define('DB_ACCOUNTS', DB_PREFIX . 'accounts');
define('DB_AUTHORIZATION', DB_PREFIX . 'authorization');
define('DB_USERCLASS', DB_PREFIX . 'userclass');
define('DB_COUNTER', DB_PREFIX . 'counter');
define('DB_MESSAGES', DB_PREFIX . 'messages');
define('DB_LOGBOOK', DB_PREFIX . 'logbook');
define('DB_SENDEPLAN', DB_PREFIX . 'sendeplan');
define('DB_TEAM', DB_PREFIX . 'team');
define('DB_SETTINGS', DB_PREFIX . 'settings');
define('DB_CHATBOX', DB_PREFIX . 'chatbox');
define('DB_CHATDATA', DB_PREFIX . 'chatdata');
define('DB_HOSTER', DB_PREFIX . 'hoster');

// System-Pfade
define('BASE_PATH', __DIR__ . '/../');
define('TEMPLATE_PATH', BASE_PATH . 'templates/');
define('UPLOAD_PATH', BASE_PATH . 'uploads/');
define('LOG_PATH', BASE_PATH . 'logs/');

// URL-Basis
define('BASE_URL', 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']) . '/');

// Timezone
date_default_timezone_set('Europe/Berlin');

?>