<?php
// ============================================================================
// DATEI: classes/SecureSession.php
// Komplette SecureSession mit Session-Reihenfolge Fix
// ============================================================================

class SecureSession {
    private Database $database;
    private string $sessionId;
    private array $sessionData = [];
    private string $csrfToken;
    private bool $isValid = false;
    
    // Sicherheits-Konstanten
    public const SESSION_LIFETIME = 7200; // 2 Stunden
    public const IDLE_TIMEOUT = 1800; // 30 Minuten Inaktivität
    public const MAX_SESSIONS_PER_USER = 3; // Max. gleichzeitige Sessions
    public const REGENERATE_INTERVAL = 300; // Session-ID alle 5 Min neu
    public const FINGERPRINT_KEYS = ['HTTP_USER_AGENT', 'HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING'];
    public const MAX_LOGIN_ATTEMPTS = 5; // Pro IP/User
    public const LOCKOUT_DURATION = 900; // 15 Minuten Sperre
    
    public function __construct(Database $database) {
        $this->database = $database;
        $this->setupSecureSession();
    }

    /**
     * Statische Methode für frühe Session-Initialisierung
     */
    public static function initializeEarly(): void {
        // Session-Konfiguration schon vor der Instanziierung setzen
        if (session_status() === PHP_SESSION_NONE) {
            ini_set('session.cookie_httponly', '1');
            ini_set('session.cookie_secure', !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? '1' : '0');
            ini_set('session.cookie_samesite', 'Strict');
            ini_set('session.use_strict_mode', '1');
            ini_set('session.use_only_cookies', '1');
            ini_set('session.name', 'WEBRADIO_SESSID');
            ini_set('session.gc_maxlifetime', (string)self::SESSION_LIFETIME);
            
            session_set_cookie_params([
                'lifetime' => self::SESSION_LIFETIME,
                'path' => '/',
                'domain' => $_SERVER['HTTP_HOST'] ?? '',
                'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
        }
    }

    /**
     * Sichere Session initialisieren
     */
    private function setupSecureSession(): void {
        // Prüfen ob Session bereits aktiv
        if (session_status() === PHP_SESSION_ACTIVE) {
            // Session beenden für saubere Neuinitialisierung
            session_write_close();
        }
        
        // Session-Konfiguration härten (nur wenn Session noch nicht aktiv)
        $this->configureSessionSecurity();
        
        // Custom Session Handler setzen
        session_set_save_handler(
            [$this, 'sessionOpen'],
            [$this, 'sessionClose'],
            [$this, 'sessionRead'],
            [$this, 'sessionWrite'],
            [$this, 'sessionDestroy'],
            [$this, 'sessionGc']
        );
        
        // Sichere Session starten
        $this->startSecureSession();
        
        // Session validieren oder erstellen
        $this->validateOrCreateSession();
    }

    /**
     * Session-Sicherheit konfigurieren
     */
    private function configureSessionSecurity(): void {
        // Nur konfigurieren wenn Session noch nicht aktiv
        if (session_status() === PHP_SESSION_NONE) {
            ini_set('session.cookie_httponly', '1');
            ini_set('session.cookie_secure', $this->isHttps() ? '1' : '0');
            ini_set('session.cookie_samesite', 'Strict');
            ini_set('session.use_strict_mode', '1');
            ini_set('session.use_only_cookies', '1');
            ini_set('session.entropy_length', '32');
            ini_set('session.hash_function', 'sha256');
            ini_set('session.gc_maxlifetime', (string)self::SESSION_LIFETIME);
            ini_set('session.name', 'WEBRADIO_SESSID');
            
            // Session-Cookie Parameter setzen
            session_set_cookie_params([
                'lifetime' => self::SESSION_LIFETIME,
                'path' => '/',
                'domain' => $_SERVER['HTTP_HOST'] ?? '',
                'secure' => $this->isHttps(),
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
        }
    }

    /**
     * Sichere Session starten
     */
    private function startSecureSession(): void {
        // Session ID regenerieren für zusätzliche Sicherheit
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
            
            // Neue Session-ID für Sicherheit
            if (!isset($_SESSION['initialized'])) {
                session_regenerate_id(true);
                $_SESSION['initialized'] = true;
                $_SESSION['created_at'] = time();
            }
        }
        
        $this->sessionId = session_id();
        
        // Session-ID Validierung
        if (!$this->isValidSessionId($this->sessionId)) {
            session_regenerate_id(true);
            $this->sessionId = session_id();
        }
    }

    /**
     * Session-ID validieren
     */
    private function isValidSessionId(string $sessionId): bool {
        // Session-ID muss mindestens 32 Zeichen haben und nur gültige Zeichen enthalten
        return strlen($sessionId) >= 32 && preg_match('/^[a-zA-Z0-9,-]+$/', $sessionId);
    }

    /**
     * Session validieren oder neue erstellen
     */
    private function validateOrCreateSession(): void {
        $session = $this->getSessionFromDB();
        
        if (!$session) {
            $this->createNewSession();
            return;
        }
        
        // Sicherheitsprüfungen
        if (!$this->validateSession($session)) {
            $this->destroySession();
            $this->createNewSession();
            return;
        }
        
        $this->sessionData = json_decode($session['data'], true) ?? [];
        $this->isValid = true;
        
        // Session-ID regelmäßig regenerieren
        if ($this->shouldRegenerateId($session)) {
            $this->regenerateSessionId();
        }
        
        // Aktivität aktualisieren
        $this->updateLastActivity();
    }

    /**
     * Session aus Datenbank abrufen
     */
    private function getSessionFromDB(): ?array {
        return $this->database->fetchArray(
            "SELECT * FROM " . TBL_USER_SESSIONS . " WHERE id = ? AND expires_at > NOW()",
            [$this->sessionId]
        ) ?: null;
    }

    /**
     * Session validieren
     */
    private function validateSession(array $session): bool {
        // IP-Bindung prüfen
        if ($session['ip_address'] !== $this->getClientIp()) {
            $this->logSecurityEvent('session_ip_mismatch', [
                'session_ip' => $session['ip_address'],
                'client_ip' => $this->getClientIp()
            ]);
            return false;
        }
        
        // Browser-Fingerprint prüfen
        if ($session['fingerprint'] !== $this->getBrowserFingerprint()) {
            $this->logSecurityEvent('session_fingerprint_mismatch', [
                'session_fp' => $session['fingerprint'],
                'client_fp' => $this->getBrowserFingerprint()
            ]);
            return false;
        }
        
        // Idle Timeout prüfen
        $lastActivity = strtotime($session['last_activity']);
        if ((time() - $lastActivity) > self::IDLE_TIMEOUT) {
            $this->logSecurityEvent('session_idle_timeout', [
                'last_activity' => $session['last_activity'],
                'timeout_seconds' => self::IDLE_TIMEOUT
            ]);
            return false;
        }
        
        // User-Agent Strict Check
        if ($session['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
            $this->logSecurityEvent('session_useragent_change', [
                'session_ua' => $session['user_agent'],
                'current_ua' => $_SERVER['HTTP_USER_AGENT'] ?? ''
            ]);
            return false;
        }
        
        return true;
    }

    /**
     * Neue Session erstellen
     */
    private function createNewSession(): void {
        $this->sessionData = [
            'created_at' => time(),
            'csrf_token' => $this->generateCsrfToken(),
            'privileges' => [],
            'flags' => [],
            'last_regeneration' => time()
        ];
        
        $this->database->query(
            "INSERT INTO " . TBL_USER_SESSIONS . " 
            (id, user_id, ip_address, user_agent, fingerprint, data, expires_at, created_at, last_activity)
            VALUES (?, NULL, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), NOW(), NOW())",
            [
                $this->sessionId,
                $this->getClientIp(),
                $_SERVER['HTTP_USER_AGENT'] ?? '',
                $this->getBrowserFingerprint(),
                json_encode($this->sessionData),
                self::SESSION_LIFETIME
            ]
        );
        
        $this->csrfToken = $this->sessionData['csrf_token'];
        $this->isValid = true;
        
        $this->logSecurityEvent('session_created');
    }

    /**
     * Benutzer anmelden (erweiterte Sicherheit)
     */
    public function loginUser(int $userId, array $privileges = [], array $additionalData = []): bool {
        // Login-Attempts prüfen
        if (!$this->checkLoginAttempts($userId)) {
            $this->logSecurityEvent('login_blocked_attempts', ['user_id' => $userId]);
            return false;
        }
        
        // Alte Sessions des Users begrenzen
        $this->limitUserSessions($userId);
        
        // Session-Daten aktualisieren
        $this->sessionData['user_id'] = $userId;
        $this->sessionData['privileges'] = $privileges;
        $this->sessionData['login_time'] = time();
        $this->sessionData['login_ip'] = $this->getClientIp();
        $this->sessionData = array_merge($this->sessionData, $additionalData);
        
        // Session in DB aktualisieren
        $this->database->query(
            "UPDATE " . TBL_USER_SESSIONS . " 
            SET user_id = ?, data = ?, last_activity = NOW()
            WHERE id = ?",
            [$userId, json_encode($this->sessionData), $this->sessionId]
        );
        
        // Login-Attempt zurücksetzen
        $this->resetLoginAttempts($userId);
        
        // Neuen CSRF-Token generieren
        $this->regenerateCsrfToken();
        
        $this->logSecurityEvent('user_login_success', ['user_id' => $userId]);
        
        return true;
    }

    /**
     * Login-Versuche prüfen (Brute-Force Schutz)
     */
    private function checkLoginAttempts(int $userId): bool {
        $ip = $this->getClientIp();
        
        // IP-basierte Attempts
        $ipAttempts = $this->database->fetchArray(
            "SELECT COUNT(*) as count, MAX(created_at) as last_attempt 
            FROM " . TBL_LOGS . " 
            WHERE level = 'warning' AND module = 'auth' 
            AND JSON_EXTRACT(context, '$.type') = 'login_failed' 
            AND ip_address = ? 
            AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)",
            [$ip, self::LOCKOUT_DURATION]
        );
        
        if (($ipAttempts['count'] ?? 0) >= self::MAX_LOGIN_ATTEMPTS) {
            $this->logSecurityEvent('login_blocked_ip', ['attempts' => $ipAttempts['count']]);
            return false;
        }
        
        // User-basierte Attempts
        $userAttempts = $this->database->fetchArray(
            "SELECT COUNT(*) as count 
            FROM " . TBL_LOGS . " 
            WHERE level = 'warning' AND module = 'auth' 
            AND JSON_EXTRACT(context, '$.type') = 'login_failed' 
            AND user_id = ? 
            AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)",
            [$userId, self::LOCKOUT_DURATION]
        );
        
        if (($userAttempts['count'] ?? 0) >= self::MAX_LOGIN_ATTEMPTS) {
            $this->logSecurityEvent('login_blocked_user', ['user_id' => $userId]);
            return false;
        }
        
        return true;
    }

    /**
     * User-Sessions begrenzen
     */
    private function limitUserSessions(int $userId): void {
        $sessions = $this->database->fetchAll(
            "SELECT id FROM " . TBL_USER_SESSIONS . " 
            WHERE user_id = ? AND expires_at > NOW() 
            ORDER BY last_activity DESC",
            [$userId]
        );
        
        if (count($sessions) >= self::MAX_SESSIONS_PER_USER) {
            // Älteste Sessions löschen
            $toDelete = array_slice($sessions, self::MAX_SESSIONS_PER_USER - 1);
            foreach ($toDelete as $session) {
                $this->database->query(
                    "DELETE FROM " . TBL_USER_SESSIONS . " WHERE id = ?",
                    [$session['id']]
                );
            }
            
            $this->logSecurityEvent('sessions_limited', [
                'user_id' => $userId,
                'deleted_count' => count($toDelete)
            ]);
        }
    }

    /**
     * CSRF Token generieren
     */
    private function generateCsrfToken(): string {
        $token = bin2hex(random_bytes(32));
        return hash_hmac('sha256', $token, $this->getServerSecret());
    }

    /**
     * CSRF Token regenerieren
     */
    public function regenerateCsrfToken(): string {
        $this->csrfToken = $this->generateCsrfToken();
        $this->sessionData['csrf_token'] = $this->csrfToken;
        $this->saveSessionData();
        return $this->csrfToken;
    }

    /**
     * CSRF Token validieren
     */
    public function validateCsrfToken(string $token): bool {
        if (!hash_equals($this->getCsrfToken(), $token)) {
            $this->logSecurityEvent('csrf_token_invalid', ['provided_token' => substr($token, 0, 10) . '...']);
            return false;
        }
        return true;
    }

    /**
     * Privilege prüfen
     */
    public function hasPrivilege(string $privilege): bool {
        return in_array($privilege, $this->sessionData['privileges'] ?? []);
    }

    /**
     * Privilege hinzufügen
     */
    public function addPrivilege(string $privilege): void {
        if (!$this->hasPrivilege($privilege)) {
            $this->sessionData['privileges'][] = $privilege;
            $this->saveSessionData();
            $this->logSecurityEvent('privilege_added', ['privilege' => $privilege]);
        }
    }

    /**
     * Privilege entfernen
     */
    public function removePrivilege(string $privilege): void {
        $privileges = $this->sessionData['privileges'] ?? [];
        $this->sessionData['privileges'] = array_values(array_diff($privileges, [$privilege]));
        $this->saveSessionData();
        $this->logSecurityEvent('privilege_removed', ['privilege' => $privilege]);
    }

    /**
     * Session-Flag setzen
     */
    public function setFlag(string $flag, $value = true): void {
        $this->sessionData['flags'][$flag] = $value;
        $this->saveSessionData();
    }

    /**
     * Session-Flag prüfen
     */
    public function hasFlag(string $flag): bool {
        return !empty($this->sessionData['flags'][$flag]);
    }

    /**
     * Browser-Fingerprint generieren
     */
    private function getBrowserFingerprint(): string {
        $fingerprint = '';
        foreach (self::FINGERPRINT_KEYS as $key) {
            $fingerprint .= $_SERVER[$key] ?? '';
        }
        return hash('sha256', $fingerprint . $this->getServerSecret());
    }

    /**
     * Client-IP ermitteln (Proxy-sicher)
     */
    private function getClientIp(): string {
        $headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    /**
     * Server-Secret für Crypto-Operationen
     */
    private function getServerSecret(): string {
        static $secret = null;
        if ($secret === null) {
            $secret = hash('sha256', 
                ($_SERVER['SERVER_NAME'] ?? 'localhost') . 
                ($_SERVER['DOCUMENT_ROOT'] ?? '') . 
                'WEBRADIO_SECRET_' . date('Y-m-d')
            );
        }
        return $secret;
    }

    /**
     * Session-ID regenerieren
     */
    private function regenerateSessionId(): void {
        $oldId = $this->sessionId;
        session_regenerate_id(true);
        $this->sessionId = session_id();
        
        // Regeneration-Zeit aktualisieren
        $this->sessionData['last_regeneration'] = time();
        
        // DB aktualisieren
        $this->database->query(
            "UPDATE " . TBL_USER_SESSIONS . " SET id = ?, data = ? WHERE id = ?",
            [$this->sessionId, json_encode($this->sessionData), $oldId]
        );
        
        $this->logSecurityEvent('session_id_regenerated', ['old_id' => substr($oldId, 0, 8) . '...']);
    }

    /**
     * Prüfen ob Session-ID regeneriert werden sollte
     */
    private function shouldRegenerateId(array $session): bool {
        $lastRegeneration = $this->sessionData['last_regeneration'] ?? 0;
        return (time() - $lastRegeneration) > self::REGENERATE_INTERVAL;
    }

    /**
     * Aktivität aktualisieren
     */
    private function updateLastActivity(): void {
        $this->database->query(
            "UPDATE " . TBL_USER_SESSIONS . " SET last_activity = NOW() WHERE id = ?",
            [$this->sessionId]
        );
    }

    /**
     * Session-Daten speichern
     */
    private function saveSessionData(): void {
        $this->database->query(
            "UPDATE " . TBL_USER_SESSIONS . " SET data = ?, last_activity = NOW() WHERE id = ?",
            [json_encode($this->sessionData), $this->sessionId]
        );
    }

    /**
     * Sicherheitsevent loggen
     */
    private function logSecurityEvent(string $event, array $context = []): void {
        $context = array_merge($context, [
            'session_id' => substr($this->sessionId, 0, 8) . '...',
            'ip_address' => $this->getClientIp(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'event' => $event,
            'timestamp' => time()
        ]);
        
        $this->database->query(
            "INSERT INTO " . TBL_LOGS . " (level, message, context, user_id, ip_address, user_agent, module)
             VALUES ('warning', ?, ?, ?, ?, ?, 'security')",
            [
                "Security Event: $event",
                json_encode($context),
                $this->getUserId(),
                $this->getClientIp(),
                $_SERVER['HTTP_USER_AGENT'] ?? ''
            ]
        );
    }

    /**
     * Login-Attempts zurücksetzen
     */
    private function resetLoginAttempts(int $userId): void {
        // Erfolgreiche Logins werden automatisch durch das Logging-System getrackt
        $this->logSecurityEvent('login_attempts_reset', ['user_id' => $userId]);
    }

    /**
     * HTTPS prüfen
     */
    private function isHttps(): bool {
        return !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    }

    // ========================================================================
    // GETTER-METHODEN
    // ========================================================================

    public function getCsrfToken(): string {
        return $this->sessionData['csrf_token'] ?? '';
    }

    public function getUserId(): ?int {
        return $this->sessionData['user_id'] ?? null;
    }

    public function getSessionData(string $key = null) {
        if ($key === null) {
            return $this->sessionData;
        }
        return $this->sessionData[$key] ?? null;
    }

    public function setSessionData(string $key, $value): void {
        $this->sessionData[$key] = $value;
        $this->saveSessionData();
    }

    public function isValid(): bool {
        return $this->isValid;
    }

    public function getSessionId(): string {
        return $this->sessionId;
    }

    // ========================================================================
    // SESSION HANDLER METHODEN
    // ========================================================================

    public function sessionOpen($path, $name): bool { 
        return true; 
    }
    
    public function sessionClose(): bool { 
        return true; 
    }
    
    public function sessionRead($id): string {
        $session = $this->database->fetchArray(
            "SELECT data FROM " . TBL_USER_SESSIONS . " WHERE id = ? AND expires_at > NOW()",
            [$id]
        );
        return $session['data'] ?? '';
    }
    
    public function sessionWrite($id, $data): bool {
        return $this->database->query(
            "INSERT INTO " . TBL_USER_SESSIONS . " (id, data, last_activity, expires_at)
             VALUES (?, ?, NOW(), DATE_ADD(NOW(), INTERVAL ? SECOND))
             ON DUPLICATE KEY UPDATE data = VALUES(data), last_activity = VALUES(last_activity)",
            [$id, $data, self::SESSION_LIFETIME]
        );
    }
    
    public function sessionDestroy($id): bool {
        return $this->database->query(
            "DELETE FROM " . TBL_USER_SESSIONS . " WHERE id = ?",
            [$id]
        );
    }
    
    public function sessionGc($max_lifetime): int {
        $this->database->query(
            "DELETE FROM " . TBL_USER_SESSIONS . " WHERE expires_at < NOW()"
        );
        return 1;
    }

    // ========================================================================
    // SESSION-MANAGEMENT
    // ========================================================================

    /**
     * Session komplett zerstören
     */
    public function destroySession(): void {
        $this->logSecurityEvent('session_destroyed');
        
        // Session aus DB löschen
        $this->sessionDestroy($this->sessionId);
        
        // PHP Session zerstören
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        
        $this->isValid = false;
        $this->sessionData = [];
    }

    /**
     * Alle Sessions eines Users zerstören
     */
    public function destroyAllUserSessions(int $userId): void {
        $this->database->query(
            "DELETE FROM " . TBL_USER_SESSIONS . " WHERE user_id = ?",
            [$userId]
        );
        
        $this->logSecurityEvent('all_user_sessions_destroyed', ['target_user_id' => $userId]);
    }

    /**
     * Session-Informationen für Admin-Panel
     */
    public function getSessionInfo(): array {
        return [
            'session_id' => substr($this->sessionId, 0, 8) . '...',
            'user_id' => $this->getUserId(),
            'created_at' => $this->sessionData['created_at'] ?? null,
            'login_time' => $this->sessionData['login_time'] ?? null,
            'login_ip' => $this->sessionData['login_ip'] ?? null,
            'current_ip' => $this->getClientIp(),
            'privileges_count' => count($this->sessionData['privileges'] ?? []),
            'flags_count' => count($this->sessionData['flags'] ?? []),
            'is_valid' => $this->isValid,
            'expires_in' => self::SESSION_LIFETIME - (time() - ($this->sessionData['created_at'] ?? time()))
        ];
    }

    /**
     * Session-Health Check
     */
    public function healthCheck(): array {
        $issues = [];
        
        // Session-Validität
        if (!$this->isValid) {
            $issues[] = 'Session ist nicht gültig';
        }
        
        // Session-Alter
        $age = time() - ($this->sessionData['created_at'] ?? time());
        if ($age > self::SESSION_LIFETIME) {
            $issues[] = 'Session ist abgelaufen';
        }
        
        // IP-Konsistenz
        $loginIp = $this->sessionData['login_ip'] ?? null;
        $currentIp = $this->getClientIp();
        if ($loginIp && $loginIp !== $currentIp) {
            $issues[] = 'IP-Adresse hat sich geändert';
        }
        
        // CSRF-Token vorhanden
        if (empty($this->sessionData['csrf_token'])) {
            $issues[] = 'CSRF-Token fehlt';
        }
        
        return [
            'healthy' => empty($issues),
            'issues' => $issues,
            'session_age' => $age,
            'time_until_expire' => self::SESSION_LIFETIME - $age
        ];
    }
}