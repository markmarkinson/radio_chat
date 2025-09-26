<?php
// ============================================================================
// DATEI: classes/Auth.php
// Komplett neu mit SecureSession Integration
// ============================================================================

class Auth {
    private Database $database;
    private SecureSession $session;
    private ?array $userCache = null;
    private ?array $privilegesCache = null;
    private ?array $rolesCache = null;
    
    public function __construct(Database $database) {
        $this->database = $database;
        $this->session = new SecureSession($database);
    }

    /**
     * Benutzer registrieren
     */
    public function register(string $username, string $email, string $password, array $options = []): array {
        // Eingabe-Validierung
        $validation = $this->validateRegistration($username, $email, $password);
        if (!$validation['valid']) {
            return $validation;
        }

        // Registrierung erlaubt?
        if (!$this->database->getSetting('users', 'allow_registration', true)) {
            return ['success' => false, 'error' => 'Registrierung ist derzeit nicht möglich'];
        }

        try {
            $this->database->beginTransaction();

            // Benutzer erstellen
            $hashedPassword = password_hash($password, PASSWORD_ARGON2ID, [
                'memory_cost' => 65536, // 64 MB
                'time_cost' => 4,       // 4 Iterationen
                'threads' => 3          // 3 Threads
            ]);

            $userId = $this->createUser([
                'username' => $username,
                'email' => $email,
                'password' => $hashedPassword,
                'display_name' => $options['display_name'] ?? $username,
                'status' => $options['status'] ?? 'active'
            ]);

            // Standard-Rolle zuweisen
            $defaultRole = $this->database->getSetting('users', 'default_role', 'user');
            $this->assignUserRole($userId, $defaultRole);

            $this->database->commit();

            // Registrierung loggen
            $this->logActivity('user_registered', "Neuer Benutzer registriert: $username", $userId);

            return [
                'success' => true,
                'user_id' => $userId,
                'message' => 'Registrierung erfolgreich'
            ];

        } catch (Exception $e) {
            $this->database->rollback();
            error_log("Registration failed: " . $e->getMessage());
            return ['success' => false, 'error' => 'Registrierung fehlgeschlagen'];
        }
    }

    /**
     * Registrierung validieren
     */
    private function validateRegistration(string $username, string $email, string $password): array {
        $errors = [];

        // Username-Validierung
        if (strlen($username) < 3 || strlen($username) > 50) {
            $errors[] = 'Benutzername muss zwischen 3 und 50 Zeichen lang sein';
        }
        
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
            $errors[] = 'Benutzername darf nur Buchstaben, Zahlen, Unterstriche und Bindestriche enthalten';
        }

        // Email-Validierung
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Ungültige E-Mail-Adresse';
        }

        // Passwort-Validierung
        $minLength = $this->database->getSetting('security', 'password_min_length', 8);
        if (strlen($password) < $minLength) {
            $errors[] = "Passwort muss mindestens $minLength Zeichen lang sein";
        }

        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/', $password)) {
            $errors[] = 'Passwort muss Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen enthalten';
        }

        // Eindeutigkeit prüfen
        if ($this->isUsernameTaken($username)) {
            $errors[] = 'Benutzername bereits vergeben';
        }

        if ($this->isEmailTaken($email)) {
            $errors[] = 'E-Mail-Adresse bereits registriert';
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'success' => empty($errors)
        ];
    }

    /**
     * Benutzer einloggen mit erweiterten Sicherheitsprüfungen
     */
    public function login(string $username, string $password, array $options = []): array {
        // Rate Limiting prüfen
        if (!$this->checkRateLimit()) {
            return ['success' => false, 'error' => 'Zu viele Login-Versuche. Bitte warten Sie.'];
        }

        // Benutzer aus DB laden
        $user = $this->loadUser($username);
        if (!$user) {
            $this->logActivity('login_failed', "Login-Versuch für unbekannten Benutzer: $username");
            $this->incrementFailedAttempts($username);
            return ['success' => false, 'error' => 'Ungültige Anmeldedaten'];
        }

        // Benutzer-Status prüfen
        if ($user['status'] !== 'active') {
            $this->logActivity('login_blocked', "Login-Versuch für gesperrten Benutzer: $username", $user['id']);
            return ['success' => false, 'error' => 'Benutzerkonto ist gesperrt'];
        }

        // Passwort prüfen
        if (!password_verify($password, $user['password'])) {
            $this->logActivity('login_failed', "Falsches Passwort für Benutzer: $username", $user['id']);
            $this->incrementFailedAttempts($username, $user['id']);
            return ['success' => false, 'error' => 'Ungültige Anmeldedaten'];
        }

        // Passwort-Upgrade prüfen
        if (password_needs_rehash($user['password'], PASSWORD_ARGON2ID)) {
            $this->upgradePassword($user['id'], $password);
        }

        // Benutzer-Privileges und Rollen laden
        $privileges = $this->loadUserPrivileges($user['id']);
        $roles = $this->loadUserRoles($user['id']);

        // Zusätzliche Session-Daten
        $sessionData = [
            'username' => $user['username'],
            'email' => $user['email'],
            'display_name' => $user['display_name'],
            'roles' => array_column($roles, 'role_name'),
            'max_role_level' => max(array_column($roles, 'role_level') ?: [0]),
            'two_factor_verified' => false,
            'password_expires' => $this->getPasswordExpiry($user['id'])
        ];

        // 2FA prüfen falls aktiviert
        if ($this->isTwoFactorEnabled($user['id'])) {
            if (empty($options['2fa_code'])) {
                // 2FA-Token generieren und per E-Mail senden
                $this->generateAndSend2FAToken($user['id']);
                return [
                    'success' => false,
                    'requires_2fa' => true,
                    'user_id' => $user['id'],
                    'message' => 'Zwei-Faktor-Authentifizierung erforderlich'
                ];
            }

            if (!$this->verify2FAToken($user['id'], $options['2fa_code'])) {
                $this->logActivity('2fa_failed', "2FA-Verifikation fehlgeschlagen", $user['id']);
                return ['success' => false, 'error' => '2FA-Code ungültig'];
            }

            $sessionData['two_factor_verified'] = true;
        }

        // Secure Session erstellen
        $loginSuccess = $this->session->loginUser($user['id'], $privileges, $sessionData);

        if (!$loginSuccess) {
            return ['success' => false, 'error' => 'Session konnte nicht erstellt werden'];
        }

        // Login-Statistiken aktualisieren
        $this->updateLoginStats($user['id']);

        // Failed attempts zurücksetzen
        $this->resetFailedAttempts($username, $user['id']);

        $this->logActivity('login_success', "Benutzer erfolgreich angemeldet", $user['id']);

        return [
            'success' => true,
            'user_id' => $user['id'],
            'username' => $user['username'],
            'requires_password_change' => $this->requiresPasswordChange($user['id']),
            'session_expires' => time() + SecureSession::SESSION_LIFETIME
        ];
    }

    /**
     * 2FA-Token verifizieren
     */
    public function verify2FAToken(int $userId, string $token): bool {
        $stored = $this->database->fetchArray(
            "SELECT token, expires_at FROM user_2fa_tokens WHERE user_id = ? AND used = 0 ORDER BY created_at DESC LIMIT 1",
            [$userId]
        );

        if (!$stored || strtotime($stored['expires_at']) < time()) {
            return false;
        }

        if (!hash_equals($stored['token'], hash('sha256', $token))) {
            return false;
        }

        // Token als verwendet markieren
        $this->database->query(
            "UPDATE user_2fa_tokens SET used = 1 WHERE user_id = ? AND token = ?",
            [$userId, $stored['token']]
        );

        return true;
    }

    /**
     * Benutzer ausloggen
     */
    public function logout(): array {
        if ($this->isLoggedIn()) {
            $userId = $this->getUserId();
            $this->logActivity('logout', "Benutzer abgemeldet", $userId);
            
            // Session zerstören
            $this->session->destroySession();
            
            // Cache leeren
            $this->clearCache();
            
            return ['success' => true, 'message' => 'Erfolgreich abgemeldet'];
        }
        
        return ['success' => false, 'error' => 'Nicht angemeldet'];
    }

    /**
     * Alle Sessions eines Benutzers beenden
     */
    public function logoutAllSessions(?int $userId = null): array {
        $targetUserId = $userId ?? $this->getUserId();
        
        if (!$targetUserId) {
            return ['success' => false, 'error' => 'Kein Benutzer angegeben'];
        }

        // Berechtigung prüfen (nur eigene Sessions oder Admin)
        if ($userId && $userId !== $this->getUserId() && !$this->hasPermission('users', 'manage_sessions')) {
            return ['success' => false, 'error' => 'Keine Berechtigung'];
        }

        $this->session->destroyAllUserSessions($targetUserId);
        $this->logActivity('logout_all_sessions', "Alle Sessions beendet", $targetUserId);

        return ['success' => true, 'message' => 'Alle Sessions beendet'];
    }

    /**
     * Passwort ändern
     */
    public function changePassword(string $currentPassword, string $newPassword, ?int $userId = null): array {
        $targetUserId = $userId ?? $this->getUserId();
        
        if (!$targetUserId) {
            return ['success' => false, 'error' => 'Nicht angemeldet'];
        }

        // Berechtigung prüfen
        if ($userId && $userId !== $this->getUserId() && !$this->hasPermission('users', 'change_password')) {
            return ['success' => false, 'error' => 'Keine Berechtigung'];
        }

        // Aktuelles Passwort prüfen (außer Admin-Override)
        if (!$userId || $userId === $this->getUserId()) {
            $user = $this->database->fetchArray(
                "SELECT password FROM " . TBL_USERS . " WHERE id = ?",
                [$targetUserId]
            );

            if (!password_verify($currentPassword, $user['password'])) {
                return ['success' => false, 'error' => 'Aktuelles Passwort ist falsch'];
            }
        }

        // Neues Passwort validieren
        $validation = $this->validatePassword($newPassword);
        if (!$validation['valid']) {
            return ['success' => false, 'errors' => $validation['errors']];
        }

        // Passwort hashen und speichern
        $hashedPassword = password_hash($newPassword, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);

        $this->database->query(
            "UPDATE " . TBL_USERS . " SET password = ?, password_changed_at = NOW() WHERE id = ?",
            [$hashedPassword, $targetUserId]
        );

        // Alle anderen Sessions des Benutzers beenden
        if ($targetUserId !== $this->getUserId()) {
            $this->session->destroyAllUserSessions($targetUserId);
        }

        $this->logActivity('password_changed', "Passwort geändert", $targetUserId);

        return ['success' => true, 'message' => 'Passwort erfolgreich geändert'];
    }

    /**
     * Berechtigung prüfen
     */
    public function hasPermission(string $module, string $action): bool {
        if (!$this->isLoggedIn()) {
            return false;
        }

        $permission = $module . '.' . $action;
        return $this->session->hasPrivilege($permission);
    }

    /**
     * Rolle prüfen
     */
    public function hasRole(string $roleName): bool {
        if (!$this->isLoggedIn()) {
            return false;
        }

        $roles = $this->session->getSessionData('roles') ?? [];
        return in_array($roleName, $roles);
    }

    /**
     * Minimum-Level prüfen
     */
    public function hasMinLevel(int $minLevel): bool {
        if (!$this->isLoggedIn()) {
            return false;
        }

        $maxLevel = $this->session->getSessionData('max_role_level') ?? 0;
        return $maxLevel >= $minLevel;
    }

    /**
     * Benutzer-Rolle zuweisen
     */
    public function assignUserRole(int $userId, string $roleName, ?DateTime $expiresAt = null, ?int $grantedBy = null): bool {
        // Rolle-ID ermitteln
        $role = $this->database->fetchArray(
            "SELECT id FROM " . TBL_ROLES . " WHERE name = ?",
            [$roleName]
        );

        if (!$role) {
            return false;
        }

        $grantedBy = $grantedBy ?? $this->getUserId();

        $this->database->query(
            "INSERT INTO " . TBL_USER_ROLES . " (user_id, role_id, granted_by, expires_at)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE 
             granted_by = VALUES(granted_by),
             granted_at = NOW(),
             expires_at = VALUES(expires_at)",
            [$userId, $role['id'], $grantedBy, $expiresAt ? $expiresAt->format('Y-m-d H:i:s') : null]
        );

        $this->logActivity('role_assigned', "Rolle '$roleName' zugewiesen", $userId);
        
        // Benutzer-Session aktualisieren falls online
        $this->refreshUserPrivileges($userId);

        return true;
    }

    /**
     * Benutzer-Rolle entfernen
     */
    public function removeUserRole(int $userId, string $roleName): bool {
        $role = $this->database->fetchArray(
            "SELECT id FROM " . TBL_ROLES . " WHERE name = ?",
            [$roleName]
        );

        if (!$role) {
            return false;
        }

        $this->database->query(
            "DELETE FROM " . TBL_USER_ROLES . " WHERE user_id = ? AND role_id = ?",
            [$userId, $role['id']]
        );

        $this->logActivity('role_removed', "Rolle '$roleName' entfernt", $userId);
        
        // Benutzer-Session aktualisieren
        $this->refreshUserPrivileges($userId);

        return true;
    }

    /**
     * Benutzer-Privileges neu laden und Session aktualisieren
     */
    public function refreshUserPrivileges(?int $userId = null): void {
        $targetUserId = $userId ?? $this->getUserId();
        
        if (!$targetUserId) {
            return;
        }

        // Neue Privileges laden
        $privileges = $this->loadUserPrivileges($targetUserId);
        $roles = $this->loadUserRoles($targetUserId);

        // Session aktualisieren falls der aktuelle Benutzer betroffen ist
        if ($targetUserId === $this->getUserId()) {
            // Privileges in Session aktualisieren
            $this->session->setSessionData('privileges', $privileges);
            $this->session->setSessionData('roles', array_column($roles, 'role_name'));
            $this->session->setSessionData('max_role_level', max(array_column($roles, 'role_level') ?: [0]));
            
            // Cache leeren
            $this->clearCache();
        }
    }

    /**
     * Aktueller Benutzer eingeloggt?
     */
    public function isLoggedIn(): bool {
        return $this->session->isValid() && $this->session->getUserId() !== null;
    }

    /**
     * Benutzer-ID abrufen
     */
    public function getUserId(): ?int {
        return $this->session->getUserId();
    }

    /**
     * Username abrufen
     */
    public function getUsername(): ?string {
        return $this->session->getSessionData('username');
    }

    /**
     * Display Name abrufen
     */
    public function getDisplayName(): ?string {
        return $this->session->getSessionData('display_name') ?? $this->getUsername();
    }

    /**
     * E-Mail abrufen
     */
    public function getEmail(): ?string {
        return $this->session->getSessionData('email');
    }

    /**
     * Benutzer-Rollen abrufen
     */
    public function getUserRoles(): array {
        if ($this->rolesCache === null) {
            $this->rolesCache = $this->session->getSessionData('roles') ?? [];
        }
        return $this->rolesCache;
    }

    /**
     * CSRF-Token abrufen
     */
    public function getCsrfToken(): string {
        return $this->session->getCsrfToken();
    }

    /**
     * CSRF-Schutz Helper
     */
    public function getCsrfProtection(): CsrfProtection {
        return new CsrfProtection($this->session);
    }

    /**
     * Session-Daten abrufen
     */
    public function getSessionData(string $key = null) {
        return $this->session->getSessionData($key);
    }

    /**
     * Session-Daten setzen
     */
    public function setSessionData(string $key, $value): void {
        $this->session->setSessionData($key, $value);
    }

    /**
     * SecureSession Instanz abrufen
     */
    public function getSession(): SecureSession {
        return $this->session;
    }

    // ========================================================================
    // PRIVATE HELPER METHODS
    // ========================================================================

    /**
     * Benutzer aus DB laden
     */
    private function loadUser(string $username): ?array {
        return $this->database->fetchArray(
            "SELECT id, username, email, password, display_name, status, created_at, last_login
             FROM " . TBL_USERS . " 
             WHERE username = ? OR email = ?",
            [$username, $username]
        ) ?: null;
    }

    /**
     * Benutzer erstellen
     */
    private function createUser(array $userData): int {
        $this->database->query(
            "INSERT INTO " . TBL_USERS . " (username, email, password, display_name, status)
             VALUES (?, ?, ?, ?, ?)",
            [
                $userData['username'],
                $userData['email'],
                $userData['password'],
                $userData['display_name'],
                $userData['status']
            ]
        );

        return $this->database->lastInsertId();
    }

    /**
     * Benutzer-Privileges aus DB laden
     */
    private function loadUserPrivileges(int $userId): array {
        if ($this->privilegesCache !== null) {
            return $this->privilegesCache;
        }

        $privileges = [];
        $permissions = $this->database->fetchAll(
            "SELECT permission_name FROM v_user_permissions WHERE user_id = ?",
            [$userId]
        );

        foreach ($permissions as $perm) {
            $privileges[] = $perm['permission_name'];
        }

        $this->privilegesCache = $privileges;
        return $privileges;
    }

    /**
     * Benutzer-Rollen aus DB laden
     */
    private function loadUserRoles(int $userId): array {
        return $this->database->fetchAll(
            "SELECT role_name, role_display_name, role_level 
             FROM v_user_roles 
             WHERE user_id = ? AND (expires_at IS NULL OR expires_at > NOW())
             ORDER BY role_level DESC",
            [$userId]
        );
    }

    /**
     * Rate Limiting prüfen
     */
    private function checkRateLimit(): bool {
        $ip = $this->getClientIp();
        $maxAttempts = $this->database->getSetting('security', 'login_attempts', 5);
        $lockoutDuration = $this->database->getSetting('security', 'lockout_duration', 900);

        $attempts = $this->database->fetchArray(
            "SELECT COUNT(*) as count FROM " . TBL_LOGS . "
             WHERE level = 'warning' 
             AND module = 'auth' 
             AND ip_address = ?
             AND context->>'$.type' IN ('login_failed', 'login_blocked')
             AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)",
            [$ip, $lockoutDuration]
        );

        return $attempts['count'] < $maxAttempts;
    }

    /**
     * Failed Attempts erhöhen
     */
    private function incrementFailedAttempts(string $username, ?int $userId = null): void {
        // Bereits durch SecureSession.logSecurityEvent abgedeckt
    }

    /**
     * Failed Attempts zurücksetzen
     */
    private function resetFailedAttempts(string $username, int $userId): void {
        // Optional: Spezielle Behandlung für erfolgreiche Logins
    }

    /**
     * Login-Statistiken aktualisieren
     */
    private function updateLoginStats(int $userId): void {
        $this->database->query(
            "UPDATE " . TBL_USERS . " 
             SET last_login = NOW(), login_count = login_count + 1 
             WHERE id = ?",
            [$userId]
        );
    }

    /**
     * Username bereits vergeben?
     */
    private function isUsernameTaken(string $username): bool {
        $count = $this->database->fetchArray(
            "SELECT COUNT(*) as count FROM " . TBL_USERS . " WHERE username = ?",
            [$username]
        );
        
        return $count['count'] > 0;
    }

    /**
     * E-Mail bereits registriert?
     */
    private function isEmailTaken(string $email): bool {
        $count = $this->database->fetchArray(
            "SELECT COUNT(*) as count FROM " . TBL_USERS . " WHERE email = ?",
            [$email]
        );
        
        return $count['count'] > 0;
    }

    /**
     * Passwort validieren
     */
    private function validatePassword(string $password): array {
        $errors = [];
        $minLength = $this->database->getSetting('security', 'password_min_length', 8);

        if (strlen($password) < $minLength) {
            $errors[] = "Passwort muss mindestens $minLength Zeichen lang sein";
        }

        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/', $password)) {
            $errors[] = 'Passwort muss Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen enthalten';
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }

    /**
     * Passwort-Upgrade durchführen
     */
    private function upgradePassword(int $userId, string $password): void {
        $newHash = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);

        $this->database->query(
            "UPDATE " . TBL_USERS . " SET password = ? WHERE id = ?",
            [$newHash, $userId]
        );

        $this->logActivity('password_upgraded', "Passwort-Hash aktualisiert", $userId);
    }

    /**
     * 2FA aktiviert?
     */
    private function isTwoFactorEnabled(int $userId): bool {
        $result = $this->database->fetchArray(
            "SELECT COUNT(*) as count FROM user_2fa_settings WHERE user_id = ? AND enabled = 1",
            [$userId]
        );
        
        return $result['count'] > 0;
    }

    /**
     * 2FA-Token generieren und senden
     */
    private function generateAndSend2FAToken(int $userId): void {
        $token = sprintf('%06d', random_int(100000, 999999));
        $hashedToken = hash('sha256', $token);

        // Token in DB speichern
        $this->database->query(
            "INSERT INTO user_2fa_tokens (user_id, token, expires_at)
             VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))",
            [$userId, $hashedToken]
        );

        // Token per E-Mail senden (Implementierung je nach Mail-System)
        $this->send2FATokenEmail($userId, $token);
    }

    /**
     * 2FA-Token per E-Mail senden
     */
    private function send2FATokenEmail(int $userId, string $token): void {
        // TODO: Implementierung des E-Mail-Versands
        // Beispiel: Mail-Service aufrufen
    }

    /**
     * Passwort-Ablauf prüfen
     */
    private function getPasswordExpiry(int $userId): ?int {
        $result = $this->database->fetchArray(
            "SELECT password_changed_at FROM " . TBL_USERS . " WHERE id = ?",
            [$userId]
        );

        if (!$result['password_changed_at']) {
            return null;
        }

        $maxAge = $this->database->getSetting('security', 'password_max_age_days', 90);
        return strtotime($result['password_changed_at']) + ($maxAge * 24 * 60 * 60);
    }

    /**
     * Passwort-Änderung erforderlich?
     */
    private function requiresPasswordChange(int $userId): bool {
        $expiry = $this->getPasswordExpiry($userId);
        return $expiry && $expiry < time();
    }

    /**
     * Client-IP ermitteln
     */
    private function getClientIp(): string {
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    /**
     * Aktivität loggen
     */
    private function logActivity(string $type, string $message, ?int $userId = null): void {
        $level = in_array($type, ['login_failed', 'login_blocked', '2fa_failed']) ? 'warning' : 'info';
        $context = [
            'ip_address' => $this->getClientIp(),
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
                $userId ?? $this->getUserId(),
                $context['ip_address'],
                $context['user_agent']
            ]
        );
    }

    /**
     * Cache leeren
     */
    private function clearCache(): void {
        $this->userCache = null;
        $this->privilegesCache = null;
        $this->rolesCache = null;
    }
}