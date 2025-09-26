<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Session starten
session_start();

// Core-System laden
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/classes/Database.php';
require_once __DIR__ . '/classes/Router.php';
require_once __DIR__ . '/classes/Template.php';
require_once __DIR__ . '/classes/Auth.php';

// Globale Instanzen erstellen
$database = new Database();
$template = new Template();
$auth = new Auth($database);
$router = new Router($database, $template, $auth);

// Aktuelle Route ermitteln
$route = $_GET['route'] ?? '';
$action = $_GET['action'] ?? 'index';

// Router ausführen
$router->handleRequest($route, $action);

?>