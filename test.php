<?php
declare(strict_types=1);

require_once __DIR__ . '/classes/RequestValidator.php';

/** Escaper: erlaubt auch null */
function h(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
/** Default-Helper für Form-Werte */
function fieldValue(string $name, mixed $default = ''): string {
    return isset($_REQUEST[$name]) ? h((string)$_REQUEST[$name]) : h((string)$default);
}
/** UI-Box */
function box(string $title, string $content, string $class = '', bool $open = false): string {
    $openAttr = $open ? ' open' : '';
    return "<details class='box {$class}'>
                <summary class='box__title'>".h($title)."</summary>
                <div class='box__body'>{$content}</div>
            </details>";
}
/** <pre> */
function pre($data): string { return '<pre>'.h(is_string($data) ? $data : print_r($data, true)).'</pre>'; }

$mode   = strtoupper((string)($_GET['mode'] ?? 'GET')); // GET | POST | FILES
$formId = $_POST['form_id'] ?? '';

$results = [
    'clean'      => [],
    'errors'     => [],
    'last_error' => null,
    'unconsumed' => [],
    'moved'      => [],
];

/* ==================== GET ==================== */
if ($mode === 'GET' && isset($_GET['submit_get'])) {
    $v = new RequestValidator('GET');

    // text + regex + min/max
    $v->validate('q', [
        'type'=>'text','required'=>true,'trim'=>true,'strip_control'=>true,'collapse_ws'=>true,
        'min_len'=>2,'max_len'=>40,'regex'=>'/^[\pL\pN _.\-]+$/u'
    ]);
    // number (int_only) + min/max
    $v->validate('min', ['type'=>'number','int_only'=>true,'min'=>0,'max'=>100]);
    // email single
    $v->validate('mail', ['type'=>'email']);
    // email multiple (per Komma/Semikolon)
    $v->validate('mails', ['type'=>'email','multiple'=>true,'min_count'=>1,'max_count'=>5,'unique'=>true]);
    // url
    $v->validate('site', ['type'=>'url']);
    // tel (relaxte Prüfung wie in Klasse)
    $v->validate('tel', ['type'=>'tel']);
    // enum (eigenständiger Typ, nicht select)
    $v->validate('env', ['type'=>'enum','required'=>true,'in'=>['dev','stage','prod']]);

    // absichtlich unvalidiertes Feld erlaubt Debug via ensureConsumed
    $results['unconsumed'] = $v->ensureConsumed();
    $results['clean']      = $v->getClean();
    $results['errors']     = $v->getErrors();
    $results['last_error'] = $v->getLastError();
}

/* ==================== POST ==================== */
if ($mode === 'POST' && $_SERVER['REQUEST_METHOD'] === 'POST' && $formId === 'post') {
    $v = new RequestValidator('POST');

    // text & textarea getrennt
    $v->validate('name',['type'=>'text','required'=>true,'trim'=>true,'min_len'=>2,'max_len'=>60,'collapse_ws'=>true]);
    $v->validate('bio',['type'=>'textarea','required'=>true,'min_len'=>10,'max_len'=>500,'allow_html'=>false]);

    // password inkl. confirm
    $v->validate('password',[
        'type'=>'password','required'=>true,'trim'=>true,'min_len'=>8,'max_len'=>100,
        'require_upper'=>true,'require_lower'=>true,'require_digit'=>true,
        'disallow_whitespace'=>true,'confirm_with'=>'password_confirm'
        // 'hash'=>true, // zum Testen aktivieren
    ]);

    // number float (kein int_only) + step-Check
    $v->validate('price',['type'=>'number','required'=>true,'min'=>0,'max'=>9999.99,'step'=>0.01]);

    // range (float)
    $v->validate('satisfaction',['type'=>'range','required'=>true,'min'=>0,'max'=>10,'step'=>1]);

    // checkbox → bool (muss gesetzt sein)
    $v->validate('agree',['type'=>'checkbox','required'=>true]);

    // radio
    $v->validate('role',['type'=>'radio','required'=>true,'in'=>['user','editor','admin']]);

    // select (single)
    $v->validate('country',['type'=>'select','required'=>true,'in'=>['de','at','ch','fr','nl']]);

    // select-multiple / checkboxes
    $v->validate('tags',[
        'type'=>'select-multiple','min_count'=>1,'max_count'=>5,'unique'=>true,
        'allowed'=>['php','js','css','html','sql','docker']
    ]);

    // url, email, tel extra
    $v->validate('website',['type'=>'url']);
    $v->validate('email',['type'=>'email','required'=>true]);
    $v->validate('phone',['type'=>'tel']);

    // date / time / datetime-local / month / week
    $v->validate('birthday',['type'=>'date','min'=>'1900-01-01','max'=>date('Y-m-d')]);
    $v->validate('meet_time',['type'=>'time']); // H:i oder H:i:s
    $v->validate('meet_at',['type'=>'datetime-local','min'=>'2020-01-01T00:00','max'=>'2100-12-31T23:59']);
    $v->validate('billing_month',['type'=>'month']); // Y-m
    $v->validate('iso_week',['type'=>'week']); // o-Wxx

    // color
    $v->validate('favorite_color',['type'=>'color']);

    // uuid
    $v->validate('uuid',['type'=>'uuid']);

    // enum (separat zu select)
    $v->validate('priority',['type'=>'enum','in'=>['low','medium','high']]);

    // array (direkt, z.B. aus checkboxes[] oder JSON-dekodiert)
    $v->validate('features',['type'=>'array','min_count'=>1,'max_count'=>5,'unique'=>true,'allowed'=>['a','b','c','d']]);

    // json (+ Schema)
    $v->validate('profile',[
        'type'=>'json','assoc'=>true,
        'schema'=>function($d){
            if(!is_array($d)) return 'Profil muss ein Objekt sein';
            if(!isset($d['bio']) || !is_string($d['bio'])) return 'profile.bio fehlt oder ist kein String';
            return '';
        }
    ]);

    $results['unconsumed'] = $v->ensureConsumed();
    $results['clean']      = $v->getClean();
    $results['errors']     = $v->getErrors();
    $results['last_error'] = $v->getLastError();
}

/* ==================== FILES ==================== */
if ($mode === 'FILES' && $_SERVER['REQUEST_METHOD'] === 'POST' && $formId === 'files') {
    $vf = new RequestValidator('FILES','8MB');

    // Einzeldatei (Bild)
    $vf->validate('avatar',[
        'type'=>'file','required'=>true,'max_size'=>'4MB',
        'ext'=>['jpg','jpeg','png','webp'],
        'mimes'=>['image/jpeg','image/png','image/webp'],
        'min_width'=>100,'min_height'=>100,'max_width'=>4000,'max_height'=>4000
    ]);

    // Mehrere Dateien
    $vf->validate('gallery',[
        'type'=>'files','min_files'=>0,'max_files'=>3,'max_size'=>'6MB',
        'ext'=>['jpg','jpeg','png','webp','gif'],
        'mimes'=>['image/jpeg','image/png','image/webp','image/gif'],
        'max_width'=>6000,'max_height'=>6000
    ]);

    $results['unconsumed'] = $vf->ensureConsumed();
    $results['clean']      = $vf->getClean();
    $results['errors']     = $vf->getErrors();
    $results['last_error'] = $vf->getLastError();

    if (empty(array_filter($results['errors']))) {
        $uploadDir = __DIR__.'/uploads';
        $m1 = $vf->moveUploaded('avatar',$uploadDir,true);
        $m2 = $vf->moveUploaded('gallery',$uploadDir,true);
        $results['moved'] = array_merge($m1,$m2);
    }
}
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>RequestValidator – Vollständiger Typen-Test</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;line-height:1.45}
.tabs{margin-bottom:18px}
.tabs a{display:inline-block;padding:8px 12px;border:1px solid #ccc;border-radius:8px;text-decoration:none;color:#333;margin-right:6px}
.tabs a.active{background:#111;color:#fff;border-color:#111}
.wrap{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:1000px){.wrap{grid-template-columns:1fr}}
fieldset{border:1px solid #ddd;padding:16px;border-radius:10px;margin-bottom:14px}
legend{padding:0 6px;color:#555}
label{display:block;font-weight:600;margin:8px 0 4px}
input,select,textarea{width:100%;padding:8px;border:1px solid #ccc;border-radius:6px}
input[type=checkbox], input[type=radio]{width:auto}
button{padding:10px 14px;border-radius:8px;border:1px solid #111;background:#111;color:#fff;cursor:pointer}
.small{font-size:.92rem;color:#666;font-weight:400}
.box{border:1px solid #eee;border-radius:10px;margin-bottom:14px}
.box__title{padding:10px 12px;border-bottom:1px solid #eee;font-weight:700;background:#fafafa}
.box__body{padding:12px}
.errors{color:#b00020}
.ok{color:#0a7a2f}
pre{white-space:pre-wrap}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
/* Details/summary Optik */
.box { border:1px solid #eee; border-radius:10px; margin-bottom:14px; overflow:hidden; }
.box__title { cursor:pointer; user-select:none; }
.box summary { list-style:none; }
.box summary::-webkit-details-marker { display:none; }

/* Pfeilindikator */
.box__title::before {
  content:"▸";
  display:inline-block;
  margin-right:.5rem;
  transform:translateY(-1px) rotate(0deg);
  transition:transform .15s ease;
}
.box[open] .box__title::before { transform:translateY(-1px) rotate(90deg); }
</style>
</head>
<body>
<h1>RequestValidator – Vollständiger Typen-Test</h1>
<div class="tabs">
    <a href="?mode=GET"   class="<?= $mode==='GET'?'active':''?>">GET</a>
    <a href="?mode=POST"  class="<?= $mode==='POST'?'active':''?>">POST</a>
    <a href="?mode=FILES" class="<?= $mode==='FILES'?'active':''?>">FILES</a>
</div>

<div class="wrap">
    <div>
        <?php if($mode==='GET'): ?>
        <!-- GET -->
        <form method="get">
            <input type="hidden" name="mode" value="GET">
            <input type="hidden" name="submit_get" value="1">
            <fieldset>
                <legend>GET-Felder</legend>
                <label>Suchstring * <input type="text" name="q" value="<?= fieldValue('q','StandardSuche')?>"></label>
                <div class="grid2">
                    <label>Min (0–100) <input type="number" name="min" value="<?= fieldValue('min','10')?>"></label>
                    <label>E-Mail <input type="email" name="mail" value="<?= fieldValue('mail','demo@example.com')?>"></label>
                </div>
                <label>E-Mails (mehrere, Komma/Semikolon) <input type="text" name="mails" value="<?= fieldValue('mails','a@mail.tld; b@mail.tld')?>"></label>
                <div class="grid2">
                    <label>Website <input type="url" name="site" value="<?= fieldValue('site','https://example.org')?>"></label>
                    <label>Telefon <input type="text" name="tel" value="<?= fieldValue('tel','+49 30 123456')?>"></label>
                </div>
                <label>Umgebung (enum) *
                    <select name="env">
                        <?php $env=$_GET['env']??'dev'; foreach(['dev','stage','prod'] as $e){$s=$env===$e?'selected':''; echo "<option value='".h($e)."' $s>".h(strtoupper($e))."</option>";} ?>
                    </select>
                </label>
                <p class="small">Du kannst zusätzliche Query-Parameter anhängen, um <code>ensureConsumed()</code> zu sehen.</p>
            </fieldset>
            <button type="submit">GET prüfen</button>
        </form>

        <?php elseif($mode==='POST'): ?>
        <!-- POST -->
        <form method="post" action="?mode=POST" novalidate>
            <input type="hidden" name="form_id" value="post">
            <fieldset>
                <legend>Texte</legend>
                <label>Name * <input type="text" name="name" value="<?= fieldValue('name','Max Mustermann')?>"></label>
                <label>Bio (textarea, 10–500) <textarea name="bio" rows="4"><?= fieldValue('bio','Ich mag PHP & Validatoren.')?></textarea></label>
                <div class="grid2">
                    <label>Passwort * <input type="password" name="password" value="DemoPass1"></label>
                    <label>Bestätigung * <input type="password" name="password_confirm" value="DemoPass1"></label>
                </div>
            </fieldset>

            <fieldset>
                <legend>Zahlen</legend>
                <div class="grid2">
                    <label>Preis (Float, step 0.01) * <input type="number" step="0.01" name="price" value="<?= fieldValue('price','19.99')?>"></label>
                    <label>Bewertung (Range 0–10) * <input type="range" min="0" max="10" step="1" name="satisfaction" value="<?= fieldValue('satisfaction','7')?>"></label>
                </div>
            </fieldset>

            <fieldset>
                <legend>Optionen</legend>
                <label><input type="checkbox" name="agree" <?= isset($_POST['agree'])?'checked':'checked'; ?>> AGB akzeptieren *</label>
                <label>Rolle *
                    <span class="small">
                        <?php $r=$_POST['role']??'user'; foreach(['user','editor','admin'] as $x){$c=$r===$x?'checked':''; echo "<label class='small'><input type='radio' name='role' value='".h($x)."' $c> ".h($x)."</label> ";} ?>
                    </span>
                </label>
                <label>Land (select) *
                    <select name="country">
                        <?php $c=$_POST['country']??'de'; foreach(['de'=>'Deutschland','at'=>'Österreich','ch'=>'Schweiz','fr'=>'Frankreich','nl'=>'Niederlande'] as $k=>$v){$s=$c===$k?'selected':''; echo "<option value='".h($k)."' $s>".h($v)."</option>";} ?>
                    </select>
                </label>
                <label>Tags (select-multiple)
                    <select name="tags[]" multiple size="5">
                        <?php $sel=$_POST['tags']??['php']; foreach(['php','js','css','html','sql','docker'] as $t){$s=in_array($t,(array)$sel,true)?'selected':''; echo "<option value='".h($t)."' $s>".h(strtoupper($t))."</option>";} ?>
                    </select>
                </label>
                <label>Priorität (enum)
                    <select name="priority">
                        <?php $p=$_POST['priority']??'medium'; foreach(['low','medium','high'] as $t){$s=$p===$t?'selected':''; echo "<option value='".h($t)."' $s>".h(ucfirst($t))."</option>";} ?>
                    </select>
                </label>
            </fieldset>

            <fieldset>
                <legend>Kontakt & Links</legend>
                <div class="grid2">
                    <label>E-Mail * <input type="email" name="email" value="<?= fieldValue('email','user@example.com')?>"></label>
                    <label>Telefon <input type="text" name="phone" value="<?= fieldValue('phone','+49 40 987654')?>"></label>
                </div>
                <label>Website <input type="url" name="website" value="<?= fieldValue('website','https://example.org')?>"></label>
            </fieldset>

            <fieldset>
                <legend>Datum/Zeit</legend>
                <div class="grid2">
                    <label>Geburtstag <input type="date" name="birthday" value="<?= fieldValue('birthday','1990-01-01')?>"></label>
                    <label>Uhrzeit <input type="time" name="meet_time" value="<?= fieldValue('meet_time','14:30')?>"></label>
                </div>
                <div class="grid2">
                    <label>Termin (datetime-local) <input type="datetime-local" name="meet_at" value="<?= fieldValue('meet_at','2030-12-31T12:00')?>"></label>
                    <label>Monat <input type="month" name="billing_month" value="<?= fieldValue('billing_month','2030-12')?>"></label>
                </div>
                <label>ISO-Woche <input type="week" name="iso_week" value="<?= fieldValue('iso_week','2030-W01')?>"></label>
            </fieldset>

            <fieldset>
                <legend>Sonstiges</legend>
                <div class="grid2">
                    <label>Farbe <input type="color" name="favorite_color" value="<?= fieldValue('favorite_color','#3366FF')?>"></label>
                    <label>UUID <input type="text" name="uuid" value="<?= fieldValue('uuid','123e4567-e89b-12d3-a456-426614174000')?>"></label>
                </div>
                <label>Features (array) – mehrere wählen:
                    <span class="small">
                        <?php $f=$_POST['features']??['a']; foreach(['a','b','c','d'] as $x){$c=in_array($x,(array)$f,true)?'checked':''; echo "<label class='small'><input type='checkbox' name='features[]' value='".h($x)."' $c> ".h(strtoupper($x))."</label> ";} ?>
                    </span>
                </label>
                <label>Profil (JSON) <textarea name="profile" rows="4"><?= fieldValue('profile','{"bio":"Hallo Welt"}')?></textarea></label>
            </fieldset>

            <button type="submit">POST prüfen</button>
        </form>

        <?php else: ?>
        <!-- FILES -->
        <form method="post" action="?mode=FILES" enctype="multipart/form-data" novalidate>
            <input type="hidden" name="form_id" value="files">
            <fieldset>
                <legend>Datei-Uploads</legend>
                <label>Avatar (JPEG/PNG/WEBP, 100–4000px, ≤4MB) * <input type="file" name="avatar" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" required></label>
                <label>Galerie (0–3, ≤6MB/Bild) <input type="file" name="gallery[]" accept=".jpg,.jpeg,.png,.webp,.gif,image/jpeg,image/png,image/webp,image/gif" multiple></label>
                <p class="small">Hinweis: Browser setzen bei Datei-Feldern keine Default-Werte.</p>
            </fieldset>
            <button type="submit">FILES prüfen & verschieben</button>
        </form>
        <?php endif; ?>
    </div>

    <div>
        <?php
        $hasErrors = !empty(array_filter($results['errors']));

        if ($mode==='GET' && isset($_GET['submit_get'])) {
            echo box('GET → Clean', pre($results['clean']));
            echo box('GET → Errors', $hasErrors ? pre($results['errors']) : '<p class="ok">Keine Fehler ✅</p>');
            if (!empty($results['unconsumed'])) echo box('GET → Unconsumed', pre($results['unconsumed']));
            if (!empty($results['last_error'])) echo box('GET → Last Error', '<p class="errors">'.h($results['last_error']).'</p>');
        }

        if ($mode==='POST' && $formId==='post') {
            echo box('POST → Clean', pre($results['clean']));
            echo box('POST → Errors', $hasErrors ? pre($results['errors']) : '<p class="ok">Keine Fehler ✅</p>');
            if (!empty($results['unconsumed'])) echo box('POST → Unconsumed', pre($results['unconsumed']));
            if (!empty($results['last_error'])) echo box('POST → Last Error', '<p class="errors">'.h($results['last_error']).'</p>');
        }

        if ($mode==='FILES' && $formId==='files') {
            echo box('FILES → Clean', pre($results['clean']));
            echo box('FILES → Errors', $hasErrors ? pre($results['errors']) : '<p class="ok">Keine Fehler ✅</p>');
            if (!empty($results['unconsumed'])) echo box('FILES → Unconsumed', pre($results['unconsumed']));
            if (!empty($results['last_error'])) echo box('FILES → Last Error', '<p class="errors">'.h($results['last_error']).'</p>');
            if (!$hasErrors && !empty($results['moved'])) {
                $rows='';
                foreach($results['moved'] as $r){
                    $ok   = !empty($r['ok']) ? '✅' : '❌';
                    $src  = h((string)($r['source'] ?? ''));
                    $tgt  = h((string)($r['target'] ?? ''));
                    $c    = h((string)($r['client_name'] ?? ''));
                    $err  = h((string)($r['error'] ?? ''));
                    $rows.="<tr><td>{$ok}</td><td>{$c}</td><td><code>{$src}</code></td><td><code>{$tgt}</code></td><td>{$err}</td></tr>";
                }
                $table="<table border='1' cellpadding='6' cellspacing='0'>
                    <thead><tr><th>OK</th><th>Client</th><th>Quelle</th><th>Ziel</th><th>Error</th></tr></thead>
                    <tbody>{$rows}</tbody></table>";
                echo box('FILES → moveUploaded()', $table);
            }
        }
        ?>
    </div>
</div>
</body>
</html>
