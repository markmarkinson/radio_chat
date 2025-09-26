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
        // Zuerst in der Radio-DB suchen (authorization)
        $this->database->switchDatabase($this->database->databases[1]);
        $authUser = $this->database->fetchArray(
            "SELECT userid, username, class FROM " . DB_AUTHORIZATION . " WHERE username = ? AND class IS NOT NULL",
            [$username]
        );

        if (empty($authUser)) {
            return false;
        }

        // Dann in der Main-DB das Passwort prüfen
        $this->database->switchDatabase($this->database->databases[0]);
        $account = $this->database->fetchArray(
            "SELECT id, acc_name, password, class FROM " . DB_ACCOUNTS . " WHERE id = ? AND class IS NOT NULL",
            [$authUser['userid']]
        );

        if (empty($account) || !password_verify($password, $account['password'])) {
            return false;
        }

        // Session-Daten setzen
        $_SESSION['userID'] = $account['id'];
        $_SESSION['userName'] = $authUser['username'];
        $_SESSION['accID'] = $account['id'];
        $_SESSION['class'] = $account['class'];
        $_SESSION['loggedIn'] = true;
        $_SESSION['loginTime'] = time();

        // Login-Zeit aktualisieren
        $this->database->query(
            "UPDATE " . DB_ACCOUNTS . " SET login = ? WHERE id = ?",
            [date('Y-m-d H:i:s'), $account['id']]
        );

        return true;
    }

    /**
     * Benutzer ausloggen
     */
    public function logout(): void {
        session_destroy();
        session_start();
    }

    /**
     * Prüfen ob Benutzer eingeloggt ist
     */
    public function isLoggedIn(): bool {
        return isset($_SESSION['loggedIn']) && $_SESSION['loggedIn'] === true;
    }

    /**
     * Prüfen ob Benutzer bestimmte Rolle hat
     */
    public function hasRole(int $requiredRole): bool {
        if (!$this->isLoggedIn()) {
            return false;
        }
        
        return (int)($_SESSION['class'] ?? 0) >= $requiredRole;
    }

    /**
     * Aktuelle Benutzer-ID abrufen
     */
    public function getUserId(): ?int {
        return $_SESSION['userID'] ?? null;
    }

    /**
     * Aktuellen Benutzernamen abrufen
     */
    public function getUsername(): ?string {
        return $_SESSION['userName'] ?? null;
    }

    /**
     * Aktuelle Benutzerklasse abrufen
     */
    public function getUserClass(): int {
        return (int)($_SESSION['class'] ?? 0);
    }
}