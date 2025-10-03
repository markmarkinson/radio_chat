<?php

class RequestValidator
{
    private string $method;          // "GET", "POST" oder "FILES"
    private array  $data;            // Kopie von $_GET / $_POST / $_FILES (wird "verbraucht")
    private array  $clean = [];      // validierte/normalisierte Werte (inkl. Files)
    private array  $errors = [];
    private ?string $lastError = null;

    // Default-Upload-Limit (Bytes) – wird im Konstruktor gesetzt
    private int $defaultMaxFileSize = 0;

    private array $messages = [
        'required'          => 'Pflichtfeld fehlt.',
        'not_string'        => 'Muss ein String sein.',
        'too_short'         => 'Zu kurz (min %s).',
        'too_long'          => 'Zu lang (max %s).',
        'regex'             => 'Ungültiges Format.',
        'not_int'           => 'Muss eine Ganzzahl sein.',
        'int_min'           => 'Zu klein (min %s).',
        'int_max'           => 'Zu groß (max %s).',
        'not_float'         => 'Muss eine Zahl sein.',
        'float_min'         => 'Zu klein (min %s).',
        'float_max'         => 'Zu groß (max %s).',
        'not_bool'          => 'Muss true/false sein.',
        'not_email'         => 'Ungültige E-Mail.',
        'enum'              => 'Ungültiger Wert (erlaubt: %s).',
        'callback'          => '%s',
        'unconsumed'        => 'Unerwartete Felder: %s',
        // pwd
        'pwd_min'           => 'Passwort ist zu kurz (min %s).',
        'pwd_max'           => 'Passwort ist zu lang (max %s).',
        'pwd_upper'         => 'Mindestens ein Großbuchstabe erforderlich.',
        'pwd_lower'         => 'Mindestens ein Kleinbuchstabe erforderlich.',
        'pwd_digit'         => 'Mindestens eine Ziffer erforderlich.',
        'pwd_special'       => 'Mindestens ein Sonderzeichen erforderlich.',
        'pwd_whitespace'    => 'Passwort darf keine Leerzeichen enthalten.',
        'pwd_common'        => 'Das Passwort ist zu häufig/unsicher.',
        'pwd_confirm'       => 'Passwort-Bestätigung stimmt nicht überein.',
        'pwd_regex'         => 'Passwort erfüllt die geforderte Regel nicht.',
        // Arrays / JSON / URL / UUID / Datum
        'not_array'         => 'Muss ein Array sein.',
        'array_min'         => 'Zu wenige Einträge (min %s).',
        'array_max'         => 'Zu viele Einträge (max %s).',
        'array_allowed'     => 'Ungültige Werte im Array.',
        'array_unique'      => 'Array darf keine Duplikate enthalten.',
        'not_json'          => 'Ungültiges JSON.',
        'not_url'           => 'Ungültige URL.',
        'not_uuid'          => 'Ungültige UUID.',
        'not_date'          => 'Ungültiges Datum/Format (%s).',
        'date_min'          => 'Datum ist zu früh (min %s).',
        'date_max'          => 'Datum ist zu spät (max %s).',

        // Dateien
        'file_missing'      => 'Keine Datei hochgeladen.',
        'file_upload'       => 'Upload-Fehler (Code %s).',
        'file_size_min'     => 'Datei zu klein (min %s).',
        'file_size_max'     => 'Datei zu groß (max %s).',
        'file_mime'         => 'Unerlaubter MIME-Typ (erlaubt: %s).',
        'file_ext'          => 'Unerlaubte Dateiendung (erlaubt: %s).',
        'file_image'        => 'Datei ist kein gültiges Bild.',
        'img_too_small'     => 'Bild zu klein (min %sx%s).',
        'img_too_large'     => 'Bild zu groß (max %sx%s).',
        'files_count_min'   => 'Zu wenige Dateien (min %s).',
        'files_count_max'   => 'Zu viele Dateien (max %s).',
    ];

    /**
     * @param string $method "GET" | "POST" | "FILES"
     * @param int|string $defaultMaxFileSize Upload-Default (z. B. "2MB", "500k", 1048576)
     */
    public function __construct(string $method = 'GET', int|string $defaultMaxFileSize = '2MB')
    {
        $method = strtoupper($method);
        $this->method = $method;
        $this->defaultMaxFileSize = is_int($defaultMaxFileSize)
            ? max(0, $defaultMaxFileSize)
            : max(0, $this->parseSizeToBytes((string)$defaultMaxFileSize));

        $this->data = match ($method) {
            'POST'  => $_POST  ?? [],
            'FILES' => $_FILES ?? [],
            default => $_GET   ?? [],
        };
    }

    /** Eigene Texte setzen (nur Keys überschreiben, die du ändern willst) */
    public function setMessages(array $map): void
    {
        $this->messages = $map + $this->messages;
    }

    /* ===================== Validierung ===================== */

    public function validate(string $name, array $rules): bool
    {
        // Fehlerliste für dieses Feld (re)initialisieren
        $this->errors[$name] = [];

        $exists   = array_key_exists($name, $this->data);
        $required = (bool)($rules['required'] ?? false);

        // Nur Vorhandensein prüfen, ohne zu konsumieren (Guard)
        if (!empty($rules['require_present'])) {
            if (!$exists) {
                return $this->fail($name, $this->msg('required'));
            }
            return true; // nichts in clean setzen, data bleibt unangetastet
        }

        if ($required && !$exists) {
            return $this->fail($name, $this->msg('required'));
        }
        if (!$exists) {
            // Feld nicht vorhanden -> clean = null, bleibt in $data unberührt (nicht konsumiert)
            $this->clean[$name] = null;
            return true;
        }

        $value = $this->data[$name];

        // trim nur für GET/POST-Strings
        if ($this->method !== 'FILES' && ($rules['trim'] ?? false) && is_string($value)) {
            $value = trim($value);
        }

        $type = $rules['type'] ?? 'string';
        $cleanVal = $this->castAndValidateType($name, $type, $value, $rules);
        if ($cleanVal === null && $this->lastError) {
            return false;
        }

        if (isset($rules['callback']) && is_callable($rules['callback'])) {
            $msg = ($rules['callback'])($cleanVal, $this->data);
            if (is_string($msg) && $msg !== '') {
                return $this->fail($name, $this->msg('callback', $msg));
            }
        }

        $this->clean[$name] = $cleanVal;
        unset($this->data[$name]); // konsumieren
        return true;
    }

    public function ensureConsumed(): array
    {
        if (empty($this->data)) return [];
        $keys = implode(', ', array_keys($this->data));
        $prefix = $this->method === 'FILES' ? '[FILES] ' : '';
        $msg  = $this->msg('unconsumed', $prefix . $keys);
        $this->errors['_unconsumed'][] = $msg;
        $this->lastError = $msg;
        return $this->errors;
    }

    public function getClean(): array
    {
        return $this->clean;
    }

    public function getErrors(): array
    {
        return $this->errors;
    }

    public function getLastError(): ?string
    {
        return $this->lastError;
    }

    /* ===================== Typen-Logik ===================== */

    private function castAndValidateType(string $name, string $type, mixed $value, array $rules): mixed
    {
        $out = null;

        // Lokale Helfer
        $sanitizeString = function (string $s) use ($rules): string {
            $s = ($rules['trim'] ?? false) ? trim($s) : $s;
            if (!empty($rules['strip_control'])) {
                $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/u', '', $s);
            }
            if (($rules['allow_html'] ?? false) === false) {
                $s = strip_tags($s, (string)($rules['strip_tags'] ?? ''));
            }
            if (!empty($rules['collapse_ws'])) {
                $s = preg_replace('/[ \t]+/u', ' ', $s);
            }
            if (($rules['lower'] ?? false) === true) $s = mb_strtolower($s);
            if (($rules['upper'] ?? false) === true) $s = mb_strtoupper($s);
            return $s;
        };

        $checkLengthPattern = function (string $s) use ($name, $rules): bool {
            $len = mb_strlen($s);
            if (!empty($rules['non_empty']) && $s === '') { $this->fail($name, $this->msg('too_short', '1')); return false; }
            if (isset($rules['min_len']) && $len < (int)$rules['min_len']) { $this->fail($name, $this->msg('too_short', (string)$rules['min_len'])); return false; }
            if (isset($rules['max_len']) && $len > (int)$rules['max_len']) { $this->fail($name, $this->msg('too_long', (string)$rules['max_len'])); return false; }
            if (isset($rules['regex']) && !preg_match($rules['regex'], $s)) { $this->fail($name, $this->msg('regex')); return false; }
            return true;
        };

        $checkMinMax = function (float|int $n) use ($name, $rules): bool {
            if (isset($rules['min']) && $n < $rules['min']) {
                $key = is_float($n) ? 'float_min' : 'int_min';
                $this->fail($name, $this->msg($key, (string)$rules['min']));
                return false;
            }
            if (isset($rules['max']) && $n > $rules['max']) {
                $key = is_float($n) ? 'float_max' : 'int_max';
                $this->fail($name, $this->msg($key, (string)$rules['max']));
                return false;
            }
            if (isset($rules['step'])) {
                $step = (float)$rules['step'];
                if ($step > 0) {
                    $base = (float)($rules['min'] ?? 0);
                    $eps  = 1e-8;
                    $mod  = fmod(((float)$n - $base), $step);
                    if (!($mod < $eps || abs($mod - $step) < $eps)) {
                        $this->fail($name, $this->msg('callback', 'Ungültiger Schrittwert (step)'));
                        return false;
                    }
                }
            }
            return true;
        };

        $toArray = function ($v): array {
            if (is_array($v)) return $v;
            if ($v === null || $v === '') return [];
            return preg_split('/[;,]\s*/u', (string)$v, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        };

        switch ($type) {
            /* ===== Texteingaben / generische HTML-Inputs ===== */
            case 'text':
            case 'textarea': {
                if (!is_string($value)) { $this->fail($name, $this->msg('not_string')); break; }
                $val = $sanitizeString($value);
                if (!$checkLengthPattern($val)) break;
                $out = $val;
                break;
            }

            /* ===== Passwort ===== */
            case 'password': {
                if (!is_string($value)) { 
                    $this->fail($name, $this->msg('not_string')); 
                    break; 
                }
                $val = ($rules['trim'] ?? false) ? trim($value) : $value;

                $len = mb_strlen($val);
                if (isset($rules['min_len']) && $len < (int)$rules['min_len']) { 
                    $this->fail($name, $this->msg('pwd_min', (string)$rules['min_len'])); 
                    break; 
                }
                if (isset($rules['max_len']) && $len > (int)$rules['max_len']) { 
                    $this->fail($name, $this->msg('pwd_max', (string)$rules['max_len'])); 
                    break; 
                }
                if (!empty($rules['require_upper']) && !preg_match('/[A-Z]/u', $val)) { 
                    $this->fail($name, $this->msg('pwd_upper')); 
                    break; 
                }
                if (!empty($rules['require_lower']) && !preg_match('/[a-z]/u', $val)) { 
                    $this->fail($name, $this->msg('pwd_lower')); 
                    break; 
                }
                if (!empty($rules['require_digit']) && !preg_match('/\d/u', $val)) { 
                    $this->fail($name, $this->msg('pwd_digit')); 
                    break; 
                }
                if (!empty($rules['require_special']) && !preg_match('/[^A-Za-z0-9]/u', $val)) { 
                    $this->fail($name, $this->msg('pwd_special')); 
                    break; 
                }
                if (!empty($rules['disallow_whitespace']) && preg_match('/\s/u', $val)) { 
                    $this->fail($name, $this->msg('pwd_whitespace')); 
                    break; 
                }
                if (isset($rules['regex']) && !preg_match($rules['regex'], $val)) { 
                    $this->fail($name, $this->msg('pwd_regex')); 
                    break; 
                }

                // Blacklist
                if (!empty($rules['deny']) && is_array($rules['deny'])) {
                    $lower = mb_strtolower($val);
                    foreach ($rules['deny'] as $bad) {
                        if ($lower === mb_strtolower((string)$bad)) { 
                            $this->fail($name, $this->msg('pwd_common')); 
                            break 2; 
                        }
                    }
                }

                $hash = null;

                // Confirm prüfen → nur dann hashen
                if (!empty($rules['confirm_with']) && is_string($rules['confirm_with'])) {
                    $otherField = $rules['confirm_with'];
                    $otherVal   = $this->data[$otherField] ?? null;
                    if (!is_string($otherVal) || $otherVal !== $val) { 
                        $this->fail($name, $this->msg('pwd_confirm')); 
                        break; 
                    }
                    unset($this->data[$otherField]);

                    $algo    = $rules['algo']    ?? PASSWORD_DEFAULT;
                    $options = $rules['options'] ?? [];
                    $hash = password_hash($val, $algo, $options);
                    if ($hash === false) { 
                        $this->fail($name, $this->msg('callback', 'Password-Hashing fehlgeschlagen.')); 
                        break; 
                    }
                }

                // Wenn Hash existiert → nehmen, sonst Original
                $out = $hash ?? $val;
                break;
        }

            /* ===== Zahlen ===== */
            case 'number': {
                $s = (string)$value;
                $isFloatLike = str_contains($s, '.') || str_contains($s, ',');
                if (!empty($rules['int_only']) && !$isFloatLike) {
                    $n = filter_var($value, FILTER_VALIDATE_INT);
                    if ($n === false) { $this->fail($name, $this->msg('not_int')); break; }
                    if (!$checkMinMax((int)$n)) break;
                    $out = (int)$n; break;
                }
                $n = filter_var(str_replace(',', '.', $s), FILTER_VALIDATE_FLOAT);
                if ($n === false) { $this->fail($name, $this->msg('not_float')); break; }
                if (!$checkMinMax((float)$n)) break;
                $out = (float)$n;
                break;
            }

            case 'range': {
                $n = filter_var(str_replace(',', '.', (string)$value), FILTER_VALIDATE_FLOAT);
                if ($n === false) { $this->fail($name, $this->msg('not_float')); break; }
                if (!$checkMinMax((float)$n)) break;
                $out = (float)$n;
                break;
            }

            /* ===== Booleans / Optionen ===== */
            case 'checkbox': {
                // Wenn "in" gesetzt ist → wie radio/select behandeln
                if (isset($rules['in']) && is_array($rules['in'])) {
                    if (!in_array($value, $rules['in'], true)) {
                        $this->fail($name, $this->msg('enum', implode(', ', $rules['in'])));
                        break;
                    }
                    $out = $value;
                } else {
                    // Standard: einzelne Checkbox → bool
                    $truthy = ['on','1',1,true,'true','yes'];
                    $out = in_array($value, $truthy, true);
                }
                break;
            }

            case 'radio': {
                $allowed = $rules['in'] ?? [];
                if (!in_array($value, $allowed, true)) { $this->fail($name, $this->msg('enum', implode(', ', $allowed))); break; }
                $out = $value;
                break;
            }

            /* ===== Select ===== */
            case 'select': {
                $allowed = $rules['in'] ?? [];
                if (!in_array($value, $allowed, true)) { $this->fail($name, $this->msg('enum', implode(', ', $allowed))); break; }
                $out = $value;
                break;
            }

            case 'select-multiple':
            case 'checkboxes': {
                // Eingabe in Array konvertieren (unterstützt "a,b,c" oder ['a','b','c'])
                $arr = is_array($value) ? $value : $toArray($value);

                // Mindest-/Maximale Anzahl
                $min = $rules['min_count'] ?? null;
                $max = $rules['max_count'] ?? null;
                if ($min !== null && count($arr) < $min) { 
                    $this->fail($name, $this->msg('array_min', (string)$min)); 
                    break; 
                }
                if ($max !== null && count($arr) > $max) { 
                    $this->fail($name, $this->msg('array_max', (string)$max)); 
                    break; 
                }

                // Duplikate verhindern
                if (!empty($rules['unique']) && count($arr) !== count(array_unique($arr, SORT_REGULAR))) {
                    $this->fail($name, $this->msg('array_unique')); 
                    break;
                }

                // "in" als Alias für "allowed" unterstützen
                $allowed = $rules['allowed'] ?? ($rules['in'] ?? null);
                if (isset($allowed) && is_array($allowed)) {
                    foreach ($arr as $v) {
                        if (!in_array($v, $allowed, true)) {
                            $this->fail($name, $this->msg('array_allowed'));
                            break 2;
                        }
                    }
                }

                // Indizes normalisieren
                $out = array_values($arr);
                break;
            }

            /* ===== Dateien ===== */
            case 'file':
            case 'files': {
                // Wenn nicht im FILES-Modus: je nach required Fehler oder null
                if ($this->method !== 'FILES') {
                    if (!($rules['required'] ?? false)) { $out = null; break; }
                    $this->fail($name, $this->msg('file_missing')); 
                    break;
                }

                // Nackt kein File-Feld? -> required beachten
                if (!is_array($value)) {
                    if (!($rules['required'] ?? false)) { $out = null; break; }
                    $this->fail($name, $this->msg('file_missing')); 
                    break;
                }

                // Erkennen, ob Mehrfach-Upload (typische $_FILES-Struktur mit name[])
                $isMulti = (
                    // Standard: $_FILES['field']['name'] ist ein Array
                    (isset($value['name']) && is_array($value['name'])) ||

                    // Bereits vor-normalisiertes Array von Dateien (selten, aber abdecken)
                    (array_is_list($value) && isset($value[0]) && is_array($value[0]) && array_key_exists('tmp_name', $value[0]))
                );

                // Validieren
                if ($isMulti) {
                    $validated = $this->validateMultipleFiles($name, $value, $rules);
                    if ($validated === null && $this->lastError) break;

                    // min_files / max_files sind bereits in validateMultipleFiles() berücksichtigt
                    // Rückgabeformat steuern
                    if (!empty($rules['force_array']) || $type === 'files') {
                        $out = $validated; // immer Array
                    } else {
                        // ohne force_array: wenn nur eine Datei, gib die eine zurück; sonst Array
                        $out = (count($validated) === 1) ? $validated[0] : $validated;
                    }
                } else {
                    // Einzeldatei
                    $validated = $this->validateSingleFile($name, $value, $rules);
                    if ($validated === null && $this->lastError) break;

                    if (!empty($rules['force_array']) || $type === 'files') {
                        // für Konsistenz optional immer als Array ausgeben
                        $out = ($validated === null) ? [] : [$validated];
                    } else {
                        $out = $validated; // einzelnes File-Array oder null (wenn optional und kein Upload)
                    }
                }
                break;
            }


            /* ===== Kontakt/Links ===== */
            case 'email': {
                if (!empty($rules['multiple'])) {
                    $list = $toArray($value);
                    if (isset($rules['min_count']) && count($list) < $rules['min_count']) { $this->fail($name, $this->msg('array_min', (string)$rules['min_count'])); break; }
                    if (isset($rules['max_count']) && count($list) > $rules['max_count']) { $this->fail($name, $this->msg('array_max', (string)$rules['max_count'])); break; }
                    $valid = [];
                    foreach ($list as $email) {
                        $e = filter_var($email, FILTER_VALIDATE_EMAIL);
                        if ($e === false) { $this->fail($name, $this->msg('not_email')); break 2; }
                        $valid[] = $e;
                    }
                    if (!empty($rules['unique'])) $valid = array_values(array_unique($valid));
                    $out = $valid; break;
                }
                $filtered = filter_var($value, FILTER_VALIDATE_EMAIL);
                if ($filtered === false) { $this->fail($name, $this->msg('not_email')); break; }
                $out = $filtered;
                break;
            }

            case 'url': {
                $filtered = filter_var($value, FILTER_VALIDATE_URL);
                if ($filtered === false) { $this->fail($name, $this->msg('not_url')); break; }
                $out = $filtered;
                break;
            }

            case 'tel': {
                if (!preg_match('/^[\d\s+\-().]{3,}$/', (string)$value)) { $this->fail($name, $this->msg('regex')); break; }
                $out = (string)$value;
                break;
            }

            /* ===== Datum/Zeit ===== */
            case 'date': {
                $s = (string)$value;
                $dt = \DateTimeImmutable::createFromFormat('Y-m-d', $s);
                $errors = \DateTimeImmutable::getLastErrors();
                if (!$dt || $errors['error_count']>0) { $this->fail($name, $this->msg('not_date', 'Y-m-d')); break; }
                if (isset($rules['min'])) {
                    $minDt = \DateTimeImmutable::createFromFormat('Y-m-d', (string)$rules['min']);
                    if ($minDt && $dt < $minDt) { $this->fail($name, $this->msg('date_min', $minDt->format('Y-m-d'))); break; }
                }
                if (isset($rules['max'])) {
                    $maxDt = \DateTimeImmutable::createFromFormat('Y-m-d', (string)$rules['max']);
                    if ($maxDt && $dt > $maxDt) { $this->fail($name, $this->msg('date_max', $maxDt->format('Y-m-d'))); break; }
                }
                $out = $dt->format('Y-m-d');
                break;
            }

            case 'time': {
                $fmt = (strlen((string)$value) === 5) ? 'H:i' : 'H:i:s';
                $dt = \DateTimeImmutable::createFromFormat($fmt, (string)$value);
                $errors = \DateTimeImmutable::getLastErrors();
                if (!$dt || $errors['error_count']>0) { $this->fail($name, $this->msg('not_date', $fmt)); break; }
                $out = $dt->format($fmt);
                break;
            }

            case 'datetime-local': {
                $s = (string)$value;
                $fmt = (strlen($s) === 16) ? 'Y-m-d\TH:i' : 'Y-m-d\TH:i:s';
                $dt = \DateTimeImmutable::createFromFormat($fmt, $s);
                $errors = \DateTimeImmutable::getLastErrors();
                if (!$dt || $errors['error_count']>0) { $this->fail($name, $this->msg('not_date', $fmt)); break; }
                if (isset($rules['min'])) {
                    $min = \DateTimeImmutable::createFromFormat($fmt, (string)$rules['min']);
                    if ($min && $dt < $min) { $this->fail($name, $this->msg('date_min', $min->format(str_replace('\T',' ',$fmt)))); break; }
                }
                if (isset($rules['max'])) {
                    $max = \DateTimeImmutable::createFromFormat($fmt, (string)$rules['max']);
                    if ($max && $dt > $max) { $this->fail($name, $this->msg('date_max', $max->format(str_replace('\T',' ',$fmt)))); break; }
                }
                $out = $dt->format(str_replace('\T', ' ', $fmt)); // "Y-m-d H:i[:s]"
                break;
            }

            case 'month': {
                $dt = \DateTimeImmutable::createFromFormat('Y-m', (string)$value);
                $errors = \DateTimeImmutable::getLastErrors();
                if (!$dt || $errors['error_count']>0) { $this->fail($name, $this->msg('not_date', 'Y-m')); break; }
                $out = $dt->format('Y-m');
                break;
            }

            case 'week': {
                if (!preg_match('/^(?<y>\d{4})-W(?<w>0[1-9]|[1-4]\d|5[0-3])$/', (string)$value)) { $this->fail($name, $this->msg('not_date', 'o-\WW')); break; }
                $out = (string)$value;
                break;
            }

            /* ===== Farbe ===== */
            case 'color': {
                if (!preg_match('/^#[0-9A-Fa-f]{6}$/', (string)$value)) { $this->fail($name, $this->msg('regex')); break; }
                $out = strtoupper((string)$value);
                break;
            }

            /* ===== Utility-/sonstige Typen ===== */
            case 'uuid': {
                if (!is_string($value) || !preg_match('/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/', $value)) {
                    $this->fail($name, $this->msg('not_uuid')); break;
                }
                $out = strtolower($value);
                break;
            }

            case 'enum': {
                $allowed = $rules['in'] ?? [];
                if (!in_array($value, $allowed, true)) { $this->fail($name, $this->msg('enum', implode(', ', $allowed))); break; }
                $out = $value;
                break;
            }

            case 'array': {
                if (!is_array($value)) { $this->fail($name, $this->msg('not_array')); break; }
                if (!empty($rules['non_empty']) && empty($value)) { $this->fail($name, $this->msg('array_min', '1')); break; }
                $min = $rules['min_count'] ?? null;
                $max = $rules['max_count'] ?? null;
                if ($min !== null && count($value) < $min) { $this->fail($name, $this->msg('array_min', (string)$min)); break; }
                if ($max !== null && count($value) > $max) { $this->fail($name, $this->msg('array_max', (string)$max)); break; }
                if (!empty($rules['unique']) && count($value) !== count(array_unique($value, SORT_REGULAR))) { $this->fail($name, $this->msg('array_unique')); break; }
                if (isset($rules['allowed']) && is_array($rules['allowed'])) {
                    foreach ($value as $v) {
                        if (!in_array($v, $rules['allowed'], true)) { $this->fail($name, $this->msg('array_allowed')); break 2; }
                    }
                }
                $out = $value;
                break;
            }

            case 'json': {
                if (!is_string($value)) { $this->fail($name, $this->msg('not_json')); break; }
                $assoc   = $rules['assoc'] ?? true;
                $decoded = json_decode($value, $assoc);
                if (json_last_error() !== JSON_ERROR_NONE) { $this->fail($name, $this->msg('not_json')); break; }
                if (isset($rules['schema']) && is_callable($rules['schema'])) {
                    $err = $rules['schema']($decoded);
                    if (is_string($err) && $err !== '') { $this->fail($name, $this->msg('callback', $err)); break; }
                }
                $out = $decoded;
                break;
            }

            /* ===== Fallback ===== */
            default: {
                // Unbekannter Typ → Rohwert
                $out = $value;
                break;
            }
        }

        return $out;
    }



    /** Einzel-Upload prüfen – nutzt Default-Max und beachtet Server-Limits (upload_max_filesize, post_max_size) */
    private function validateSingleFile(string $name, mixed $file, array $rules): mixed
    {
        if (!is_array($file) || !isset($file['error'])) {
            return $this->fail($name, $this->msg('file_missing')) ? null : null;
        }

        $err = (int)$file['error'];
        if ($err === UPLOAD_ERR_NO_FILE) {
            if (!($rules['required'] ?? false)) return null;
            return $this->fail($name, $this->msg('file_missing')) ? null : null;
        }
        if ($err !== UPLOAD_ERR_OK) {
            return $this->fail($name, $this->msg('file_upload', (string)$err)) ? null : null;
        }

        $clientName = (string)($file['name'] ?? '');
        $tmp        = (string)($file['tmp_name'] ?? '');

        // Früh prüfen: Muss echter Upload sein
        if ($tmp === '' || !is_uploaded_file($tmp)) {
            return $this->fail($name, $this->msg('file_upload', 'not_uploaded')) ? null : null;
        }

        // Limits sammeln
        $size       = (int)$file['size'];
        $minSize    = $this->normalizeSizeRule($rules['min_size'] ?? 0);
        $maxSizeReq = $this->normalizeSizeRule($rules['max_size'] ?? $this->defaultMaxFileSize);
        $serverCap  = $this->getEffectiveUploadCeilingBytes(); // min(upload_max_filesize, post_max_size) oder 0, wenn unbekannt

        // Effektiv anwendbares Max = min(Anforderungs-Max, Server-Cap), wenn Server-Cap > 0
        $effectiveMax = $maxSizeReq;
        if ($serverCap > 0) {
            $effectiveMax = min($effectiveMax, $serverCap);
        }

        if ($minSize > 0 && $size < $minSize) {
            return $this->fail($name, $this->msg('file_size_min', $this->bytesToHuman($minSize))) ? null : null;
        }
        if ($effectiveMax > 0 && $size > $effectiveMax) {
            return $this->fail($name, $this->msg('file_size_max', $this->bytesToHuman($effectiveMax))) ? null : null;
        }

        // Dateiname/Extension
        $ext = strtolower(pathinfo($clientName, PATHINFO_EXTENSION));
        if (isset($rules['ext']) && is_array($rules['ext'])) {
            $allowedExt = array_map('strtolower', $rules['ext']);
            if (!in_array($ext, $allowedExt, true)) {
                return $this->fail($name, $this->msg('file_ext', implode(', ', $rules['ext']))) ? null : null;
            }
        }

        // MIME via finfo
        $mime = null;
        if ($tmp !== '' && is_file($tmp)) {
            $finfo = new \finfo(FILEINFO_MIME_TYPE);
            $mime  = $finfo->file($tmp) ?: null;
        }
        if (isset($rules['mimes']) && is_array($rules['mimes'])) {
            if (!$mime || !in_array($mime, $rules['mimes'], true)) {
                return $this->fail($name, $this->msg('file_mime', implode(', ', $rules['mimes']))) ? null : null;
            }
        }

        // Auto-Bilderkennung + Dimensions-Checks nur, wenn Bild
        $isSvg   = ($ext === 'svg') || ($mime === 'image/svg+xml');
        $isImage = $isSvg || ($mime && str_starts_with((string)$mime, 'image/')) ||
                   ($ext !== '' && in_array($ext, ['jpg','jpeg','png','gif','webp','bmp','tiff','tif'], true));

        $width = $height = null;
        if ($isImage && !$isSvg) {
            $info = @getimagesize($tmp);
            if ($info !== false) {
                [$width, $height] = $info;
                if (isset($rules['min_width'], $rules['min_height']) &&
                    ($width < (int)$rules['min_width'] || $height < (int)$rules['min_height'])) {
                    return $this->fail($name, $this->msg('img_too_small', (string)$rules['min_width'], (string)$rules['min_height'])) ? null : null;
                }
                if (isset($rules['max_width'], $rules['max_height']) &&
                    ($width > (int)$rules['max_width'] || $height > (int)$rules['max_height'])) {
                    return $this->fail($name, $this->msg('img_too_large', (string)$rules['max_width'], (string)$rules['max_height'])) ? null : null;
                }
            } else {
                return $this->fail($name, $this->msg('file_image')) ? null : null;
            }
        }

        return [
            'client_name' => $clientName,
            'ext'         => $ext,
            'mime'        => $mime ?? (string)($file['type'] ?? ''),
            'size'        => $size,
            'tmp_name'    => $tmp,
            'width'       => $width,
            'height'      => $height,
        ];
    }

    private function validateMultipleFiles(string $name, mixed $fileField, array $rules): mixed
    {
        if (!is_array($fileField) || !isset($fileField['name']) || !is_array($fileField['name'])) {
            return $this->fail($name, $this->msg('file_missing')) ? null : null;
        }

        $count = count($fileField['name']);
        $clean = [];

        for ($i = 0; $i < $count; $i++) {
            $single = [
                'name'     => $fileField['name'][$i]     ?? null,
                'type'     => $fileField['type'][$i]     ?? null,
                'tmp_name' => $fileField['tmp_name'][$i] ?? null,
                'error'    => $fileField['error'][$i]    ?? UPLOAD_ERR_NO_FILE,
                'size'     => $fileField['size'][$i]     ?? 0,
            ];
            if ((int)$single['error'] === UPLOAD_ERR_NO_FILE) {
                continue;
            }
            $one = $this->validateSingleFile($name, $single, $rules);
            if ($one === null && $this->lastError) {
                return null;
            }
            $clean[] = $one;
        }

        $min = $rules['min_files'] ?? null;
        $max = $rules['max_files'] ?? null;
        if ($min !== null && count($clean) < $min) {
            return $this->fail($name, $this->msg('files_count_min', (string)$min)) ? null : null;
        }
        if ($max !== null && count($clean) > $max) {
            return $this->fail($name, $this->msg('files_count_max', (string)$max)) ? null : null;
        }

        return $clean;
    }

    /* ===================== Fehler & Messages ===================== */

    private function fail(string $field, string $msg): bool
    {
        $this->errors[$field] ??= [];
        $this->errors[$field][] = $msg;
        $this->lastError = $msg;
        return false;
    }

    private function msg(string $key, mixed ...$args): string
    {
        $tpl = $this->messages[$key] ?? $key;
        return vsprintf($tpl, $args);
    }

    /**
     * Verschiebe Upload(s) eines Feldes – NUR aus bereits validiertem $this->clean.
     * @return array Je Datei: ['ok'=>bool,'source'=>string,'target'=>string,'client_name'=>string,'error'=>?string]
     */
    public function moveUploaded(string $field, string $uploadDir, bool $useOriginalName = true): array
    {
        $results = [];

        // Zielordner vorbereiten (Side-Effect ist okay hier, da wir jetzt wirklich verschieben wollen)
        if (!is_dir($uploadDir)) {
            if (!@mkdir($uploadDir, 0777, true) && !is_dir($uploadDir)) {
                return [[
                    'ok' => false, 'source' => '', 'target' => '', 'client_name' => '',
                    'error' => 'Zielordner konnte nicht erstellt werden',
                ]];
            }
        }

        // Preflight & Zielpfade berechnen
        $plans = $this->normalizeFilesFromData($field, $uploadDir, $useOriginalName);

        foreach ($plans as $plan) {
            if (!$plan['ok']) {
                // Preflight-Fehler unverändert durchreichen
                $results[] = $plan;
                continue;
            }

            $src    = $plan['source'];
            $target = $plan['target'];

            if (!@move_uploaded_file($src, $target)) {
                $results[] = [
                    'ok' => false,
                    'source' => $src,
                    'target' => $target,
                    'client_name' => $plan['client_name'],
                    'error' => 'move_uploaded_file fehlgeschlagen',
                ];
                continue;
            }

            @chmod($target, 0644);

            $results[] = [
                'ok' => true,
                'source' => $src,
                'target' => $target,
                'client_name' => $plan['client_name'],
                'error' => null,
            ];
        }

        return $results;
    }

    /* ===================== Upload-Helfer ===================== */

    /** Sicheren Dateinamen erzeugen (intern) */
    private function safeFilename(string $name): string
    {
        $name = preg_replace('/[^\w.\-]+/u', '_', $name) ?? '';
        $name = ltrim($name, '.'); // keine versteckten/gefährlichen Punktdateien
        if ($name === '') $name = 'file_' . uniqid('', true);

        // sehr lange Namen kappen (Dateisystem-freundlich)
        if (mb_strlen($name) > 180) {
            $pi = pathinfo($name);
            $base = mb_substr($pi['filename'] ?? 'file', 0, 150);
            $ext  = isset($pi['extension']) && $pi['extension'] !== '' ? ('.' . $pi['extension']) : '';
            $name = $base . $ext;
        }
        return $name;
    }

    /** Normalisiert validierte Uploads aus $this->clean[$field] in eine Einzelliste */
    private function normalizeFilesFromData(string $field, string $uploadDir, bool $useOriginalName = true): array
    {
        $plans = [];

        // Feld muss validiert worden sein (clean-only Contract)
        if (!array_key_exists($field, $this->clean)) {
            return [[
                'ok' => false, 'source' => '', 'target' => '', 'client_name' => '',
                'error' => "Feld '{$field}' nicht validiert oder fehlt",
            ]];
        }
        if ($this->clean[$field] === null) {
            return [[
                'ok' => false, 'source' => '', 'target' => '', 'client_name' => '',
                'error' => "Feld '{$field}' nicht vorhanden oder leer",
            ]];
        }

        $pushPlan = function (array $one) use (&$plans, $uploadDir, $useOriginalName) {
            $clientName = (string)($one['client_name'] ?? ($one['name'] ?? ''));
            $tmp        = (string)($one['tmp_name']    ?? '');
            $size       = (int)   ($one['size']        ?? 0);

            // Preflight-Checks (keine Moves!)
            if ($tmp === '' || !is_uploaded_file($tmp)) {
                $plans[] = [
                    'ok' => false, 'source' => $tmp, 'target' => '', 'client_name' => $clientName,
                    'error' => 'tmp ist keine Upload-Datei (is_uploaded_file fehlgeschlagen)',
                ];
                return;
            }

            // Zielname erzeugen (Originalname oder generiert)
            if ($useOriginalName && $clientName !== '') {
                $base = $this->safeFilename($clientName);
            } else {
                $ext  = strtolower(pathinfo($clientName, PATHINFO_EXTENSION));
                $base = 'upload_' . uniqid('', true) . ($ext !== '' ? ('.' . $ext) : '');
            }

            // Kollisionssicheren Zielpfad berechnen (ohne zu schreiben)
            $dir    = rtrim($uploadDir, '/\\');
            $target = $dir . DIRECTORY_SEPARATOR . $base;

            if (file_exists($target)) {
                $pi   = pathinfo($base);
                $name = $pi['filename'] ?? 'file';
                $ext  = isset($pi['extension']) && $pi['extension'] !== '' ? ('.' . $pi['extension']) : '';
                $target = $dir . DIRECTORY_SEPARATOR . $name . '_' . uniqid('', true) . $ext;
            }

            $plans[] = [
                'ok' => true, 'source' => $tmp, 'target' => $target, 'client_name' => $clientName,
                'error' => null,
            ];
        };

        $c = $this->clean[$field];

        // Einzel-Datei
        if (is_array($c) && isset($c['tmp_name'])) {
            $pushPlan($c);
            return $plans;
        }

        // Mehrere Dateien
        if (is_array($c)) {
            foreach ($c as $one) {
                if (is_array($one) && isset($one['tmp_name'])) {
                    $pushPlan($one);
                }
            }
        }

        if (empty($plans)) {
            $plans[] = [
                'ok' => false, 'source' => '', 'target' => '', 'client_name' => '',
                'error' => "Feld '{$field}' enthält keine verschiebbaren Dateien",
            ];
        }

        return $plans;
    }


    /* ===================== Größen/INI-Tools ===================== */

    /** "5MB", "500k", "2 GiB", "1.5TB" -> Bytes (int). Unterstützt B,K,M,G,T,P sowie KiB, MiB, ... */
    private function parseSizeToBytes(string $val): int
    {
        $v = trim($val);
        if ($v === '') return 0;

        if (!preg_match('/^\s*([\d]+(?:[.,]\d+)?)\s*([KMGTP]?)(I?B)?\s*$/i', $v, $m)) {
            // auch PHP-Notation wie "2M", "512K"
            return $this->parsePhpIniSize($v);
        }

        $num = (float)str_replace(',', '.', $m[1]);
        $unit = strtoupper($m[2] ?? '');
        $ib   = strtoupper($m[3] ?? '');

        $pow = match ($unit) {
            'K' => 1,
            'M' => 2,
            'G' => 3,
            'T' => 4,
            'P' => 5,
            default => 0,
        };
        $base = ($ib === 'IB') ? 1024 : 1000;

        return (int)round($num * (($pow > 0) ? pow($base, $pow) : 1));
    }

    /** PHP-ini Notation wie "2M", "512K", "1G" -> Bytes */
    private function parsePhpIniSize(string $val): int
    {
        $v = trim($val);
        if ($v === '' || $v === '-1') return 0; // -1 bedeutet "unbegrenzt"
        if (preg_match('/^\s*([+-]?\d+)\s*([KMG])?\s*$/i', $v, $m)) {
            $n = (int)$m[1];
            $unit = strtoupper($m[2] ?? '');
            return match ($unit) {
                'K' => $n * 1024,
                'M' => $n * 1024 * 1024,
                'G' => $n * 1024 * 1024 * 1024,
                default => $n,
            };
        }
        // Fallback: versuche generischen Parser
        return $this->parseSizeToBytes($v);
    }

    /** Größe aus Regel (int Bytes oder String) -> Bytes (int, >=0) */
    private function normalizeSizeRule(int|string $rule): int
    {
        return is_int($rule) ? max(0, $rule) : max(0, $this->parseSizeToBytes($rule));
    }

    /** Liest upload_max_filesize / post_max_size und gibt das wirksame Ceiling in Bytes zurück (min der beiden). 0 = unbekannt/unbegrenzt */
    private function getEffectiveUploadCeilingBytes(): int
    {
        $u = $this->parsePhpIniSize((string)ini_get('upload_max_filesize'));
        $p = $this->parsePhpIniSize((string)ini_get('post_max_size'));
        $vals = array_filter([$u, $p], fn($x) => $x > 0);
        if (empty($vals)) return 0;
        return min($vals);
    }

    /** Bytes hübsch formatiert, z. B. 1.23 MB */
    private function bytesToHuman(int $bytes): string
    {
        if ($bytes < 1024) return $bytes . ' B';
        $units = ['KB','MB','GB','TB','PB'];
        $i = 0;
        $val = $bytes / 1024;
        while ($val >= 1024 && $i < count($units) - 1) {
            $val /= 1024; $i++;
        }
        return number_format($val, ($val < 10 ? 2 : 1), ',', '') . ' ' . $units[$i];
    }
}
