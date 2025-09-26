<?php
class Router {
    private Database $database;
    private Template $template;
    private Auth $auth;
    private array $routes;

    public function __construct(Database $database, Template $template, Auth $auth) {
        $this->database = $database;
        $this->template = $template;
        $this->auth = $auth;
        $this->setupRoutes();
    }

    private function setupRoutes(): void {
        $this->routes = [
            '' => ['controller' => 'HomeController', 'method' => 'index'],
            'home' => ['controller' => 'HomeController', 'method' => 'index'],
            'login' => ['controller' => 'AuthController', 'method' => 'login'],
            'logout' => ['controller' => 'AuthController', 'method' => 'logout'],
            'register' => ['controller' => 'AuthController', 'method' => 'register'],
            'dashboard' => ['controller' => 'DashboardController', 'method' => 'index', 'auth' => true],
            'admin' => ['controller' => 'AdminController', 'method' => 'index', 'auth' => true, 'role' => ADMINSTATOR],
            'users' => ['controller' => 'UserController', 'method' => 'index', 'auth' => true],
            'profile' => ['controller' => 'ProfileController', 'method' => 'index', 'auth' => true],
            'sendeplan' => ['controller' => 'SendeplanController', 'method' => 'index'],
            'api' => ['controller' => 'ApiController', 'method' => 'handle'],
        ];
    }

    public function handleRequest(string $route, string $action): void {
        // Route normalisieren
        $route = trim($route, '/');
        
        // Standard-Route wenn leer
        if (empty($route)) {
            $route = 'home';
        }

        // Route existiert?
        if (!isset($this->routes[$route])) {
            $this->handle404();
            return;
        }

        $routeConfig = $this->routes[$route];

        // Authentifizierung prüfen
        if (isset($routeConfig['auth']) && $routeConfig['auth']) {
            if (!$this->auth->isLoggedIn()) {
                $this->redirectToLogin();
                return;
            }

            // Rolle prüfen
            if (isset($routeConfig['role']) && !$this->auth->hasRole($routeConfig['role'])) {
                $this->handleUnauthorized();
                return;
            }
        }

        // Controller laden und ausführen
        $this->executeController($routeConfig['controller'], $action);
    }

    private function executeController(string $controllerName, string $action): void {
        $controllerFile = BASE_PATH . 'controllers/' . $controllerName . '.php';
        
        if (!file_exists($controllerFile)) {
            // Fallback: Einfache Template-Ausgabe
            $this->handleSimpleRoute($controllerName, $action);
            return;
        }

        require_once $controllerFile;
        
        if (!class_exists($controllerName)) {
            $this->handle500("Controller-Klasse {$controllerName} nicht gefunden");
            return;
        }

        $controller = new $controllerName($this->database, $this->template, $this->auth);
        
        if (!method_exists($controller, $action)) {
            $action = 'index'; // Fallback zur index-Methode
        }

        if (method_exists($controller, $action)) {
            $controller->$action();
        } else {
            $this->handle404();
        }
    }

    private function handleSimpleRoute(string $controllerName, string $action): void {
        // Einfache Template-basierte Routen (wie im Original-System)
        $templateName = strtolower(str_replace('Controller', '', $controllerName));
        
        // Template-Datei suchen
        $templateFile = TEMPLATE_PATH . $templateName . '.tpl';
        
        if (file_exists($templateFile)) {
            $this->template->header();
            echo $this->template->render($templateName . '.tpl');
            $this->template->footer();
        } else {
            $this->handle404();
        }
    }

    private function redirectToLogin(): void {
        header('Location: ' . BASE_URL . '?route=login');
        exit;
    }

    private function handleUnauthorized(): void {
        http_response_code(403);
        $this->template->error("Zugriff verweigert", "Sie haben keine Berechtigung für diese Seite.", "?route=dashboard");
    }

    private function handle404(): void {
        http_response_code(404);
        $this->template->error("Seite nicht gefunden", "Die angeforderte Seite wurde nicht gefunden.", "?route=home");
    }

    private function handle500(string $message): void {
        http_response_code(500);
        error_log("Server Error: " . $message);
        $this->template->error("Serverfehler", "Es ist ein interner Fehler aufgetreten.", "?route=home");
    }
}
?>