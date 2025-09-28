<?php

class Database
{
    private PDO $connection;

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
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];

        try {
            $this->connection = new PDO($dsn, $this->username, $this->password, $options);
            $this->connection->exec(
                "SET SESSION sql_mode = 'STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'"
            );
        } catch (Throwable $e) {
            throw new RuntimeException('DB-Verbindung fehlgeschlagen: ' . $e->getMessage(), (int)$e->getCode(), $e);
        }
    }

    /* ===================== DML/Queries ===================== */

    public function query(string $sql, array $params = []): int
    {
        if (!preg_match('/^\s*(INSERT|UPDATE|DELETE)\b/i', $sql)) {
            $this->logError('query', $sql, $params, 'query() nur für INSERT/UPDATE/DELETE erlaubt.');
            return -1;
        }

        $stmt = $this->connection->prepare($sql);
        $this->bind($stmt, $params);
        $stmt->execute();

        if (preg_match('/^\s*INSERT\b/i', $sql)) {
            $id = $this->connection->lastInsertId();
            return is_numeric($id) ? (int)$id : 0;
        }
        return $stmt->rowCount();
    }

    public function fetchArray(string $sql, array $params = []): array
    {
        if (!preg_match('/^\s*SELECT\b/i', $sql)) {
            $this->logError('fetchArray', $sql, $params, 'fetchArray() nur mit SELECT nutzen.');
            return [];
        }

        $stmt = $this->connection->prepare($sql);
        $this->bind($stmt, $params);
        $stmt->execute();
        $row = $stmt->fetch();
        return $row === false ? [] : $row;
    }

    public function fetchAll(string $sql, array $params = []): array
    {
        if (!preg_match('/^\s*SELECT\b/i', $sql)) {
            $this->logError('fetchAll', $sql, $params, 'fetchAll() nur mit SELECT nutzen.');
            return [];
        }

        $stmt = $this->connection->prepare($sql);
        $this->bind($stmt, $params);
        $stmt->execute();
        $rows = $stmt->fetchAll();
        return $rows === false ? [] : $rows;
    }

    public function numRows(string $sql, array $params = []): int
    {
        if (!preg_match('/^\s*SELECT\b/i', $sql)) {
            $this->logError('numRows', $sql, $params, 'numRows() nur mit SELECT nutzen.');
            return 0;
        }

        if (preg_match('/^\s*SELECT\s+COUNT\(\*\)/i', $sql)) {
            $stmt = $this->connection->prepare($sql);
            $this->bind($stmt, $params);
            $stmt->execute();
            $val = $stmt->fetchColumn();
            return $val !== false ? (int)$val : 0;
        }

        $countSql = preg_replace('/\s+ORDER\s+BY\s+[\s\S]+$/i', '', $sql);
        $countSql = "SELECT COUNT(*) AS cnt FROM ( {$countSql} ) t";

        $stmt = $this->connection->prepare($countSql);
        $this->bind($stmt, $params);
        $stmt->execute();
        $row = $stmt->fetch();
        return isset($row['cnt']) ? (int)$row['cnt'] : 0;
    }

    public function lastInsertId(): int
    {
        return (int)$this->connection->lastInsertId();
    }

    /* ===================== Transaktionen ===================== */

    public function beginTransaction(): bool
    {
        return $this->connection->beginTransaction();
    }

    public function commit(): bool
    {
        return $this->connection->commit();
    }

    public function rollback(): bool
    {
        return $this->connection->rollBack();
    }

    public function transaction(callable $fn)
    {
        $this->beginTransaction();
        try {
            $result = $fn($this);
            $this->commit();
            return $result;
        } catch (Throwable $e) {
            $this->rollback();
            $this->logError('transaction', 'callable', [], $e->getMessage(), (int)$e->getCode());
            return false;
        }
    }

    /* ===================== intern ===================== */

    private function bind(PDOStatement $stmt, array $params): void
    {
        foreach ($params as $key => $value) {
            $param = is_int($key) ? $key + 1 : (string)$key;
            $type = is_int($value) ? PDO::PARAM_INT
                 : (is_bool($value) ? PDO::PARAM_BOOL
                 : (is_null($value) ? PDO::PARAM_NULL
                 : (is_resource($value) ? PDO::PARAM_LOB : PDO::PARAM_STR)));
            $stmt->bindValue($param, $value, $type);
        }
    }

    private function logError(string $method, string $sql, array $params, string $message, int $code = 0): void
    {
        $masked = [];
        foreach ($params as $k => $v) {
            $isSecretKey = is_string($k) && preg_match('/pass|secret|token/i', $k);
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

        $row = $this->fetchArray("SELECT `value`, `type` FROM " . TBL_SETTINGS . " WHERE `category` = ? AND `key` = ? LIMIT 1", [$category, $key]);

        if (!$row || !isset($row['value'])) {
            return $default;
        }

        $type = strtolower(trim((string)($row['type'] ?? 'string')));
        $allowed = ['string','boolean','integer','json'];
        if (!in_array($type, $allowed, true)) {
            $type = 'string';
        }

        $value = $row['value'];
        $result = $default; // fallback

        switch ($type) {
            case 'boolean':
                $bool = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
                if ($bool !== null) {
                    $result = $bool;
                }
                break;

            case 'integer':
                $int = filter_var($value, FILTER_VALIDATE_INT);
                if ($int !== false) {
                    $result = (int)$int;
                }
                break;

            case 'json':
                $decoded = json_decode((string)$value, true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    $result = $decoded;
                }
                break;

            case 'string':
            default:
                $result = (string)$value;
                break;
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

            case 'string':
            default:
                $value = (string)$value;
                break;
        }

        $sql = "INSERT INTO " . TBL_SETTINGS . " (`category`, `key`, `value`, `type`, `updated_at`)
                VALUES (?, ?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), `type` = VALUES(`type`), `updated_at` = NOW()";

        $result = $this->query($sql, [$category, $key, $value, $type]);
        return $result >= 0;
    }

    public function close(): void
    {
        $this->connection = null;
    }
}
