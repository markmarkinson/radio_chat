<?php
class Auth {
    private Database $database;
    
    public function __construct(Database $database) {
        $this->database = $database;
    }

    /**
     * Benutzer einloggen
     */
    public function login(string $username, string $password): bool {
        $user = $this->database->fetchArray(
            "SELECT id, username, email, password, status FROM " . TBL_USERS . " WHERE username = ? AND status = 'active'",
            [$username]
        );

        if (empty($user) || !password_verify($password, $user['password'])) {
            // Login-Versuch loggen
            $this->logActivity('login_failed', 'Login-Versuch fehlgeschlagen für: ' . $username);
            return false;
        }

        // Session-Daten setzen
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['logged_in'] = true;
        $_SESSION['login_time'] = time();

        // Login-Zeit und Counter aktualisieren
        $this->database->query(
            "UPDATE " . TBL_USERS . " SET last_login = NOW(), login_count = login_count + 1 WHERE id = ?",
            [$user['id']]
        );

        // Session in DB speichern
        $this->createSession();
        
        // Erfolgreichen Login loggen
        $this->logActivity('login_success', 'Benutzer erfolgreich angemeldet');

        return true;
    }

    /**
     * Benutzer ausloggen
     */
    public function logout(): void {
        if ($this->isLoggedIn()) {
            $this->logActivity('logout', 'Benutzer abgemeldet');
            
            // Session aus DB löschen
            $this->destroySession();
        }
        
        session_destroy();
        session_start();
    }

    /**
     * Prüfen ob Benutzer eingeloggt ist
     */
    public function isLoggedIn(): bool {
        return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    }

    /**
     * Benutzer-Berechtigung prüfen
     */
    public function hasPermission(string $module, string $action): bool {
        if (!$this->isLoggedIn()) {
            return false;
        }

        $result = $this->database->fetchArray(
            "SELECT COUNT(*) as count FROM v_user_permissions 
             WHERE user_id = ? AND module = ? AND action = ?",
            [$this->getUserId(), $module, $action]
        );

        return $result['count'] > 0;
    }

    /**
     * Rolle des Benutzers prüfen
     */
    public function hasRole(string $roleName): bool {
        if (!$this->isLoggedIn()) {
            return false;
        }

        $result = $this->database->fetchArray(
            "SELECT COUNT(*) as count FROM v_user_roles 
             WHERE user_id = ? AND role_name = ? AND (expires_at IS NULL OR expires_at > NOW())",
            [$this->getUserId(), $roleName]
        );

        return $result['count'] > 0;
    }

    /**
     * Minimum-Level prüfen
     */
    public function hasMinLevel(int $minLevel): bool {
        if (!$this->isLoggedIn()) {
            return false;
        }

        $result = $this->database->fetchArray(
            "SELECT MAX(role_level) as max_level FROM v_user_roles 
             WHERE user_id = ? AND (expires_at IS NULL OR expires_at > NOW())",
            [$this->getUserId()]
        );

        return ($result['max_level'] ?? 0) >= $minLevel;
    }

    /**
     * Aktuelle Benutzer-ID abrufen
     */
    public function getUserId(): ?int {
        return $_SESSION['user_id'] ?? null;
    }

    /**
     * Aktuellen Benutzernamen abrufen
     */
    public function getUsername(): ?string {
        return $_SESSION['username'] ?? null;
    }

    /**
     * Benutzer-Rollen abrufen
     */
    public function getUserRoles(): array {
        if (!$this->isLoggedIn()) {
            return [];
        }

        return $this->database->fetchAll(
            "SELECT role_name, role_display_name, role_level FROM v_user_roles 
             WHERE user_id = ? AND (expires_at IS NULL OR expires_at > NOW())
             ORDER BY role_level DESC",
            [$this->getUserId()]
        );
    }

    /**
     * Session in Datenbank erstellen
     */
    private function createSession(): void {
        $sessionId = session_id();
        $userId = $this->getUserId();
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        $this->database->query(
            "INSERT INTO " . TBL_USER_SESSIONS . " (id, user_id, ip_address, user_agent, expires_at)
             VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 2 HOUR))
             ON DUPLICATE KEY UPDATE 
             user_id = VALUES(user_id), 
             ip_address = VALUES(ip_address),
             user_agent = VALUES(user_agent),
             last_activity = NOW(),
             expires_at = VALUES(expires_at)",
            [$sessionId, $userId, $ipAddress, $userAgent]
        );
    }

    /**
     * Session aus Datenbank löschen
     */
    private function destroySession(): void {
        $sessionId = session_id();
        $this->database->query(
            "DELETE FROM " . TBL_USER_SESSIONS . " WHERE id = ?",
            [$sessionId]
        );
    }

    /**
     * Aktivität loggen
     */
    private function logActivity(string $type, string $message): void {
        $level = ($type === 'login_failed') ? 'warning' : 'info';
        $context = [
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'type' => $type
        ];

        $this->database->query(
            "INSERT INTO " . TBL_LOGS . " (level, message, context, user_id, ip_address, user_agent, module)
             VALUES (?, ?, ?, ?, ?, ?, 'auth')",
            [
                $level,
                $message,
                json_encode($context),
                $this->getUserId(),
                $context['ip_address'],
                $context['user_agent']
            ]
        );
    }
}