<?php

class Database
{
    private PDO $connection;
    private ?PDOStatement $lastStatement = null;

    private string $host;
    private string $username;
    private string $password;
    private string $database;
    private string $charset;

    private array $errorlog = [];

    public function __construct()
    {
        $missing = [];
        foreach (['DB_HOST','DB_USER','DB_PASS','DB_NAME','DB_CHARSET'] as $const) {
            if (!defined($const)) {
                $missing[] = $const;
            }
        }
        if ($missing) {
            // Harte Exception im Konstruktor
            throw new RuntimeException("Fehlende Konstanten: " . implode(', ', $missing));
        }

        $this->host     = (string)DB_HOST;
        $this->username = (string)DB_USER;
        $this->password = (string)DB_PASS;
        $this->database = (string)DB_NAME;
        $this->charset  = (string)DB_CHARSET;

        $this->connect();
    }

    private function connect(): void
    {
        $dsn = "mysql:host={$this->host};dbname={$this->database};charset={$this->charset}";

        // Silent Mode: keine Exceptions bei prepare/execute/etc.
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_SILENT,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];

        // Wenn der PDO-Konstruktor fehlschlägt, wirft er eine PDOException.
        // Wir lassen sie durchlaufen, d.h. es knallt hier – wie gefordert ohne try/catch.
        $this->connection = new PDO($dsn, $this->username, $this->password, $options);

        // Session-Mode setzen; bei Fehler explizit RuntimeException werfen
        $ok = $this->connection->exec(
            "SET SESSION sql_mode = 'STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'"
        );
        if ($ok === false) {
            throw new RuntimeException('Konnte SQL_MODE nicht setzen.');
        }
    }

    /* ===================== DML/Queries ===================== */

    /**
     * INSERT/UPDATE/DELETE/REPLACE ausführen.
     * Bei INSERT: lastInsertId (int), sonst rowCount(). Fehler: -1.
     * Setzt KEIN $lastStatement.
     */
    public function query(string $sql, array $params = []): int
    {
        if (!preg_match('/^\s*(INSERT|UPDATE|DELETE|REPLACE)\b/i', $sql)) {
            $this->logError('query', $sql, $params, 'query() nur für INSERT/UPDATE/DELETE/REPLACE erlaubt.');
            return -1;
        }

        $stmt = $this->connection->prepare($sql);
        if ($stmt === false) {
            $this->logError('query', $sql, $params, 'prepare() fehlgeschlagen.');
            return -1;
        }

        if (!$this->bind($stmt, $params)) {
            $this->logError('query', $sql, $params, 'bind() fehlgeschlagen.');
            return -1;
        }

        if ($stmt->execute() === false) {
            $this->logError('query', $sql, $params, 'execute() fehlgeschlagen.');
            return -1;
        }

        if (preg_match('/^\s*INSERT\b/i', $sql)) {
            $id = $this->connection->lastInsertId();
            return is_numeric($id) ? (int)$id : 0;
        }
        $this->lastStatement = null;
        return $stmt->rowCount();
    }

    /**
     * Eine Zeile als assoc-Array. Leerer $sql -> weiterlesen aus letztem SELECT.
     * Fehler: [].
     */
    public function fetchArray(string $sql, array $params = []): array
    {
        if ($sql === '') {
            if (!$this->lastStatement) {
                return [];
            }
            $row = $this->lastStatement->fetch();
            return $row === false ? [] : $row;
        }

        if (!preg_match('/^\s*(SELECT|WITH)\b/i', $sql)) {
            $this->logError('fetchArray', $sql, $params, 'fetchArray() nur mit SELECT/CTE nutzen.');
            return [];
        }

        $stmt = $this->connection->prepare($sql);
        if ($stmt === false) {
            $this->logError('fetchArray', $sql, $params, 'prepare() fehlgeschlagen.');
            return [];
        }

        if (!$this->bind($stmt, $params)) {
            $this->logError('fetchArray', $sql, $params, 'bind() fehlgeschlagen.');
            return [];
        }

        if ($stmt->execute() === false) {
            $this->logError('fetchArray', $sql, $params, 'execute() fehlgeschlagen.');
            return [];
        }

        $this->lastStatement = $stmt;

        $row = $stmt->fetch();
        return $row === false ? [] : $row;
    }

    /**
     * Alle Zeilen. Leerer $sql -> aus letztem SELECT lesen.
     * Fehler: [].
     */
    public function fetchAll(string $sql, array $params = []): array
    {
        if ($sql === '') {
            if (!$this->lastStatement) {
                return [];
            }
            $rows = $this->lastStatement->fetchAll();
            return $rows === false ? [] : $rows;
        }

        if (!preg_match('/^\s*(SELECT|WITH)\b/i', $sql)) {
            $this->logError('fetchAll', $sql, $params, 'fetchAll() nur mit SELECT/CTE nutzen.');
            return [];
        }

        $stmt = $this->connection->prepare($sql);
        if ($stmt === false) {
            $this->logError('fetchAll', $sql, $params, 'prepare() fehlgeschlagen.');
            return [];
        }

        if (!$this->bind($stmt, $params)) {
            $this->logError('fetchAll', $sql, $params, 'bind() fehlgeschlagen.');
            return [];
        }

        if ($stmt->execute() === false) {
            $this->logError('fetchAll', $sql, $params, 'execute() fehlgeschlagen.');
            return [];
        }

        $this->lastStatement = $stmt;

        $rows = $stmt->fetchAll();
        return $rows === false ? [] : $rows;
    }

    /**
     * Anzahl Zeilen, die ein SELECT liefern würde.
     * - leerer $sql: rowCount() des letzten Statements (falls vorhanden)
     * - bei COUNT(*) im SQL: direktes fetchColumn()
     * - sonst: COUNT(*) über Subselect (ORDER BY entfernt)
     * Fehler: 0
     */
    public function numRows(string $sql, array $params = []): int
    {
        if ($sql === '') {
            if (!$this->lastStatement) {
                return 0;
            }
            return $this->lastStatement->rowCount();
        }

        if (!preg_match('/^\s*(SELECT|WITH)\b/i', $sql)) {
            $this->logError('numRows', $sql, $params, 'numRows() nur mit SELECT/CTE nutzen.');
            return 0;
        }

        // Direkter COUNT(*)?
        if (preg_match('/^\s*(SELECT|WITH)\b[\s\S]*?COUNT\(\*\)/i', $sql)) {
            $stmt = $this->connection->prepare($sql);
            if ($stmt === false) {
                $this->logError('numRows', $sql, $params, 'prepare() fehlgeschlagen.');
                return 0;
            }
            if (!$this->bind($stmt, $params) || $stmt->execute() === false) {
                $this->logError('numRows', $sql, $params, 'execute()/bind() fehlgeschlagen.');
                return 0;
            }
            $this->lastStatement = $stmt;
            $val = $stmt->fetchColumn();
            return $val !== false ? (int)$val : 0;
        }

        $stmt = $this->connection->prepare($sql);
        if ($stmt === false) {
            $this->logError('numRows', $sql, $params, 'prepare() fehlgeschlagen.');
            return 0;
        }

        if (!$this->bind($stmt, $params) || $stmt->execute() === false) {
            $this->logError('numRows', $countSql, $params, 'execute()/bind() fehlgeschlagen.');
            return 0;
        }

        $this->lastStatement = $stmt;
        $row = $stmt->fetch();
        return isset($row['cnt']) ? (int)$row['cnt'] : 0;
    }

    public function lastInsertId(): int
    {
        $id = $this->connection->lastInsertId();
        return is_numeric($id) ? (int)$id : 0;
    }

    /* ===================== Transaktionen ===================== */

    public function beginTransaction(): bool
    {
        $ok = $this->connection->beginTransaction();
        if ($ok === false) {
            $this->logError('beginTransaction', '', [], 'beginTransaction() fehlgeschlagen.');
        }
        return (bool)$ok;
    }

    public function commit(): bool
    {
        $ok = $this->connection->commit();
        if ($ok === false) {
            $this->logError('commit', '', [], 'commit() fehlgeschlagen.');
        }
        return (bool)$ok;
    }

    public function rollback(): bool
    {
        $ok = $this->connection->rollBack();
        if ($ok === false) {
            $this->logError('rollback', '', [], 'rollBack() fehlgeschlagen.');
        }
        return (bool)$ok;
    }

    /**
     * Führt $fn transaktional aus. Bei Fehlern wird geloggt und false zurückgegeben.
     */
    public function transaction(callable $fn): mixed
    {
        if (!$this->beginTransaction()) {
            return false;
        }

        $result = null;
        try {
            // kein try/catch gewünscht – aber wir müssen PHP-Throwable aus *deinem* Callback abfangen?
            // Du wolltest ohne try/catch: Dann laufen Exceptions aus $fn nach außen!
            // Wenn du sie abfangen willst, sag kurz Bescheid.
            $result = $fn($this);
        } finally {
            // Falls $fn eine Exception wirft, rollBack versuchen (silent)
            if ($this->connection->inTransaction()) {
                // Bei Fehler loggen
                if ($this->connection->rollBack() === false) {
                    $this->logError('transaction', 'rollback', [], 'rollBack() im finally fehlgeschlagen.');
                }
            }
        }

        if ($this->connection->inTransaction()) {
            if (!$this->commit()) {
                return false;
            }
        }

        return $result;
    }

    /* ===================== intern ===================== */

    private function bind(PDOStatement $stmt, array $params): bool
    {
        foreach ($params as $key => $value) {
            $param = is_int($key) ? $key + 1 : (string)$key;
            $type = is_int($value) ? PDO::PARAM_INT
                 : (is_bool($value) ? PDO::PARAM_BOOL
                 : (is_null($value) ? PDO::PARAM_NULL
                 : (is_resource($value) ? PDO::PARAM_LOB : PDO::PARAM_STR)));
            if ($stmt->bindValue($param, $value, $type) === false) {
                return false;
            }
        }
        return true;
    }

    private function logError(string $method, string $sql, array $params, string $message, int $code = 0): void
    {
        $masked = [];
        foreach ($params as $k => $v) {
            $isSecretKey = is_string($k) && preg_match('/pass|secret|token|pwd|authorization|api[_-]?key|bearer/i', $k);
            if ($isSecretKey) {
                $masked[$k] = '***';
                continue;
            }
            $masked[$k] = is_string($v) && mb_strlen($v) > 200 ? mb_substr($v, 0, 200) . '…' : $v;
        }

        $this->errorlog[] = [
            'time'    => date('c'),
            'method'  => $method,
            'message' => $message,
            'code'    => $code,
            'params'  => $masked,
            'sql'     => $sql,
        ];
    }

    public function getErrors(): array
    {
        return $this->errorlog;
    }

    /* ===================== Settings-API ===================== */

    public function getSetting(string $category, string $key, $default = null)
    {
        if ($category === '' || $key === '' || !defined('TBL_SETTINGS')) {
            $this->logError('getSetting', '', [$category, $key], 'Ungültige Parameter oder TBL_SETTINGS nicht definiert');
            return $default;
        }

        $row = $this->fetchArray(
            "SELECT `value`, `type` FROM " . TBL_SETTINGS . " WHERE `category` = ? AND `key` = ? LIMIT 1",
            [$category, $key]
        );

        if (!$row || !isset($row['value'])) {
            return $default;
        }

        $type = strtolower(trim((string)($row['type'] ?? 'string')));
        $allowed = ['string','boolean','integer','json'];
        if (!in_array($type, $allowed, true)) {
            $type = 'string';
        }

        $value = $row['value'];
        $result = $default;

        switch ($type) {
            case 'boolean':
                $bool = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
                if ($bool !== null) $result = $bool;
                break;
            case 'integer':
                $int = filter_var($value, FILTER_VALIDATE_INT);
                if ($int !== false) $result = (int)$int;
                break;
            case 'json':
                $decoded = json_decode((string)$value, true);
                if (json_last_error() === JSON_ERROR_NONE) $result = $decoded;
                break;
            default:
                $result = (string)$value;
        }

        return $result;
    }

    public function setSetting(string $category, string $key, $value, string $type = 'string'): bool
    {
        if ($category === '' || $key === '' || !defined('TBL_SETTINGS')) {
            $this->logError('setSetting', '', [$category, $key, $value], 'Ungültige Parameter oder TBL_SETTINGS nicht definiert');
            return false;
        }

        $type = strtolower(trim($type));
        $allowed = ['string','boolean','integer','json'];
        if (!in_array($type, $allowed, true)) {
            $type = 'string';
        }

        switch ($type) {
            case 'boolean':
                $bool = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
                if ($bool === null) $bool = (bool)$value;
                $value = $bool ? 'true' : 'false';
                break;

            case 'integer':
                if (!is_int($value)) {
                    $int = filter_var($value, FILTER_VALIDATE_INT);
                    if ($int === false) return false;
                    $value = (string)$int;
                } else {
                    $value = (string)$value;
                }
                break;

            case 'json':
                $encoded = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                if ($encoded === false) return false;
                $value = $encoded;
                break;

            default:
                $value = (string)$value;
        }

        $sql = "INSERT INTO " . TBL_SETTINGS . " (`category`, `key`, `value`, `type`, `updated_at`)
                VALUES (?, ?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), `type` = VALUES(`type`), `updated_at` = NOW()";

        $result = $this->query($sql, [$category, $key, $value, $type]);
        return $result >= 0;
    }

    public function close(): void
    {
        // Verbindung absichtlich NICHT auf null setzen -> Property ist non-nullable.
        $this->lastStatement = null;
    }
}
