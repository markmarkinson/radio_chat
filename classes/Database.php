<?php
class Database {
    public $connection;
    public $database;
    public array $databases;
    private $host;
    private $username;
    private $password;
    private $charset;

    public function __construct() {
        $this->host = DB_HOST;
        $this->username = DB_USER;
        $this->password = DB_PASS;
        $this->charset = DB_CHARSET;
        
        // Verfügbare Datenbanken (wie im Original)
        $this->databases = [
            0 => DB_NAME_MAIN,   // Haupt-DB für Accounts
            1 => DB_NAME_RADIO   // Radio-DB für Radio-spezifische Daten
        ];
        
        // Standardmäßig zur ersten Datenbank verbinden
        $this->database = $this->databases[0];
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
            die("Datenbankverbindung fehlgeschlagen: " . $e->getMessage());
        }
    }

    /**
     * Datenbank wechseln (wie im Original-System)
     */
    public function switchDatabase(string $dbName): bool {
        if ($this->database !== $dbName) {
            $this->database = $dbName;
            try {
                $this->connection->exec("USE `{$dbName}`");
                return true;
            } catch (PDOException $e) {
                error_log("Database switch failed: " . $e->getMessage());
                return false;
            }
        }
        return true;
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
     * Einzelnen Datensatz abrufen (wie fetchArray im Original)
     */
    public function fetchArray(string $sql, $params = []): array {
        try {
            $stmt = $this->connection->prepare($sql);
            
            // Parameter können als Array oder einzelner Wert übergeben werden
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
     * Alle Datensätze abrufen (wie fetchAll im Original)
     */
    public function fetchAll(string $sql = "", array $params = []): array {
        try {
            // Wenn kein SQL übergeben wurde, vorherige Query wiederverwenden
            if (empty($sql)) {
                if (!isset($this->lastStatement)) {
                    return [];
                }
                return $this->lastStatement->fetchAll();
            }

            $stmt = $this->connection->prepare($sql);
            $stmt->execute($params);
            $this->lastStatement = $stmt; // Für nachfolgende fetchAll() Aufrufe ohne Parameter
            
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
     * Verbindung schließen
     */
    public function close(): void {
        $this->connection = null;
    }
}