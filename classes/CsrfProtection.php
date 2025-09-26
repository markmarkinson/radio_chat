<?php
class CsrfProtection {
    private SecureSession $session;

    public function __construct(SecureSession $session) {
        $this->session = $session;
    }

    /**
     * CSRF-Token für Formulare generieren
     */
    public function generateTokenField(): string {
        $token = $this->session->getCsrfToken();
        return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
    }

    /**
     * CSRF-Token für AJAX generieren
     */
    public function generateTokenMeta(): string {
        $token = $this->session->getCsrfToken();
        return '<meta name="csrf-token" content="' . htmlspecialchars($token) . '">';
    }

    /**
     * CSRF-Token aus Request validieren
     */
    public function validateRequest(): bool {
        $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        return $this->session->validateCsrfToken($token);
    }

    /**
     * Middleware für automatische CSRF-Prüfung
     */
    public function enforceForPosts(): void {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$this->validateRequest()) {
            http_response_code(403);
            die(json_encode(['error' => 'CSRF-Token ungültig']));
        }
    }
}
