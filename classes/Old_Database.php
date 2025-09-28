<?php
class Database {
    public $connection;
    private $host;
    private $username;
    private $password;
    private $database;
    private $charset;
    private $lastStatement;

    public function __construct() {
        $this->host = DB_HOST;
        $this->username = DB_USER;
        $this->password = DB_PASS;
        $this->database = DB_NAME;
        $this->charset = DB_CHARSET;
        
        $this->connect();
    }

    private function connect(): void {
        try {
            $dsn = "mysql:host={$this->host};dbname={$this->database};charset={$this->charset}";
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$this->charset}"
            ];
            
            $this->connection = new PDO($dsn, $this->username, $this->password, $options);
        } catch (PDOException $e) {
            error_log("Datenbankverbindung fehlgeschlagen: " . $e->getMessage());
            die("Datenbankfehler - bitte versuchen Sie es später erneut.");
        }
    }

    /**
     * Query ausführen mit Prepared Statements
     */
    public function query(string $sql, array $params = []): bool {
        try {
            $stmt = $this->connection->prepare($sql);
            return $stmt->execute($params);
        } catch (PDOException $e) {
            error_log("Query failed: " . $e->getMessage() . " SQL: " . $sql);
            return false;
        }
    }

    /**
     * Einzelnen Datensatz abrufen
     */
    public function fetchArray(string $sql, $params = []): array {
        try {
            $stmt = $this->connection->prepare($sql);
            
            if (!is_array($params)) {
                $params = [$params];
            }
            
            $stmt->execute($params);
            return $stmt->fetch() ?: [];
        } catch (PDOException $e) {
            error_log("FetchArray failed: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Alle Datensätze abrufen
     */
    public function fetchAll(string $sql = "", array $params = []): array {
        try {
            if (empty($sql)) {
                if (!isset($this->lastStatement)) {
                    return [];
                }
                return $this->lastStatement->fetchAll();
            }

            $stmt = $this->connection->prepare($sql);
            $stmt->execute($params);
            $this->lastStatement = $stmt;
            
            return $stmt->fetchAll();
        } catch (PDOException $e) {
            error_log("FetchAll failed: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Anzahl der Zeilen ermitteln
     */
    public function numRows(string $sql, array $params = []): int {
        try {
            $stmt = $this->connection->prepare($sql);
            $stmt->execute($params);
            return $stmt->rowCount();
        } catch (PDOException $e) {
            error_log("NumRows failed: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * Letzte Insert-ID abrufen
     */
    public function lastInsertId(): int {
        return (int) $this->connection->lastInsertId();
    }

    /**
     * Transaktion starten
     */
    public function beginTransaction(): bool {
        return $this->connection->beginTransaction();
    }

    /**
     * Transaktion bestätigen
     */
    public function commit(): bool {
        return $this->connection->commit();
    }

    /**
     * Transaktion rückgängig machen
     */
    public function rollback(): bool {
        return $this->connection->rollBack();
    }

    /**
     * Einstellung aus der Datenbank abrufen
     */
    public function getSetting(string $category, string $key, $default = null) {
        $result = $this->fetchArray(
            "SELECT value, type FROM " . TBL_SETTINGS . " WHERE category = ? AND `key` = ?",
            [$category, $key]
        );
        
        if (empty($result)) {
            return $default;
        }
        
        // Typ-Konvertierung
        switch ($result['type']) {
            case 'boolean':
                return filter_var($result['value'], FILTER_VALIDATE_BOOLEAN);
            case 'integer':
                return (int) $result['value'];
            case 'json':
                return json_decode($result['value'], true);
            default:
                return $result['value'];
        }
    }

    /**
     * Einstellung in der Datenbank setzen
     */
    public function setSetting(string $category, string $key, $value, string $type = 'string'): bool {
        // Wert entsprechend dem Typ konvertieren
        switch ($type) {
            case 'boolean':
                $value = $value ? 'true' : 'false';
                break;
            case 'json':
                $value = json_encode($value);
                break;
            default:
                $value = (string) $value;
        }
        
        return $this->query(
            "INSERT INTO " . TBL_SETTINGS . " (category, `key`, value, type, updated_at) 
             VALUES (?, ?, ?, ?, NOW()) 
             ON DUPLICATE KEY UPDATE value = VALUES(value), type = VALUES(type), updated_at = NOW()",
            [$category, $key, $value, $type]
        );
    }

    /**
     * Verbindung schließen
     */
    public function close(): void {
        $this->connection = null;
    }
}