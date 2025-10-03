<?php
declare(strict_types=1);
require_once __DIR__ . '/classes/RequestValidator.php';

/* ===== Helpers ===== */
function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function fieldValue(string $name, mixed $default = '', array $src = null): string {
    $src ??= $_REQUEST; return isset($src[$name]) ? h((string)$src[$name]) : h((string)$default);
}
function box(string $title, string $content, string $class = '', bool $open = false): string {
    $openAttr = $open ? ' open' : ''; return "<details class='box {$class}'{$openAttr}><summary class='box__title'>".h($title)."</summary><div class='box__body'>{$content}</div></details>";
}
function pre($data): string { return '<pre>'.h(is_string($data) ? $data : print_r($data, true)).'</pre>'; }

/* ===== Server-State ===== */
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$mode   = $_GET['mode'] ?? 'GET';
$formId = $_POST['form_id'] ?? '';

/* ===== Validator (nimmt echte HTTP-Methode; für API simulieren wir unten) ===== */
$v = new RequestValidator(null, '8MB');

$results = [
    'http_method' => $method,
    'tab'         => $mode,
    'clean'       => [],
    'errors'      => [],
    'last_error'  => null,
    'unconsumed'  => [],
    'moved'       => [],
    'api_method'  => null,
];

/* --- GET --- */
if ($mode === 'GET' && isset($_GET['submit_get'])) {
    $v->validate('q',     ['type'=>'text','required'=>true,'trim'=>true,'min_len'=>2,'max_len'=>40,'regex'=>'/^[a-zA-Z0-9_.\- ]+$/']);
    $v->validate('page',  ['type'=>'number','int_only'=>true,'min'=>1,'max'=>9999]);
    $v->validate('email', ['type'=>'email']);
    $results['unconsumed'] = $v->ensureConsumed();
    $results['clean']      = $v->getClean();
    $results['errors']     = $v->getErrors();
    $results['last_error'] = $v->getLastError();
}

/* --- POST --- */
if ($mode === 'POST' && $method === 'POST' && $formId === 'post') {
    $v->validate('name',   ['type'=>'text','required'=>true,'trim'=>true,'min_len'=>2,'max_len'=>60,'regex'=>'/^[a-zA-Z0-9 _.\-]+$/']);
    $v->validate('agree',  ['type'=>'checkbox','required'=>true]);
    $v->validate('role',   ['type'=>'radio','required'=>true,'in'=>['user','editor','admin']]);
    $v->validate('tags',   ['type'=>'select-multiple','min_count'=>1,'max_count'=>4,'unique'=>true,'in'=>['php','js','css','html','sql','docker']]);
    $v->validate('price',  ['type'=>'number','min'=>0,'max'=>99999,'step'=>0.01]);
    $v->validate('website',['type'=>'url']);
    $v->validate('password',[
        'type'=>'password','required'=>true,'trim'=>true,'min_len'=>8,
        'require_upper'=>true,'require_lower'=>true,'require_digit'=>true,
        'disallow_whitespace'=>true,'confirm_with'=>'password_confirm'
    ]);
    $results['unconsumed'] = $v->ensureConsumed();
    $results['clean']      = $v->getClean();
    $results['errors']     = $v->getErrors();
    $results['last_error'] = $v->getLastError();
}

/* --- FILES --- */
if ($mode === 'FILES' && $method === 'POST' && $formId === 'files') {
    $v->validate('avatar',[
        'type'=>'file','required'=>true,'max_size'=>'4MB',
        'ext'=>['jpg','jpeg','png','webp'],
        'mimes'=>['image/jpeg','image/png','image/webp'],
        'min_width'=>100,'min_height'=>100,'max_width'=>4000,'max_height'=>4000
    ]);
    $v->validate('attachments',[
        'type'=>'file','max_files'=>5,'max_size'=>'8MB','force_array'=>true,
        'ext'=>['jpg','jpeg','png','gif','pdf'],
        'mimes'=>['image/jpeg','image/png','image/gif','application/pdf']
    ]);
    $results['unconsumed'] = $v->ensureConsumed();
    $results['clean']      = $v->getClean();
    $results['errors']     = $v->getErrors();
    $results['last_error'] = $v->getLastError();
    if (empty(array_filter($results['errors']))) {
        $uploadDir = __DIR__ . '/uploads';
        $m1 = $v->moveUploaded('avatar',      $uploadDir, true);
        $m2 = $v->moveUploaded('attachments', $uploadDir, true);
        $results['moved'] = array_merge($m1, $m2);
    }
}

/* --- API (wie die anderen Tabs, per POST-Formular; Body-JSON wird decodiert & geprüft) --- */
if ($mode === 'API' && $method === 'POST' && $formId === 'api') {
    $apiMethod = strtoupper((string)($_POST['_api_method'] ?? 'PUT'));     // Anzeigezweck
    $rawBody   = (string)($_POST['_api_body'] ?? '');
    $payload   = json_decode($rawBody, true);
    if (!is_array($payload)) {
        // JSON-Fehler direkt als Validator-Fehler modellieren
        $results['errors']['_body'][] = 'Ungültiges JSON im Body.';
    } else {
        // Simulation: Wir prüfen das Payload-Array wie POST-Daten
        // Kurz $_POST sichern und überschreiben
        $backupPOST = $_POST;
        $_POST = $payload;

        // eigener Validator für API-Block (POST-Modus, damit er $_POST nutzt)
        $vApi = new RequestValidator('POST');

        // Beispiel-API-Validierungen (wie zuvor)
        $vApi->validate('title',  ['type'=>'text','required'=>true,'trim'=>true,'min_len'=>2,'max_len'=>120]);
        $vApi->validate('status', ['type'=>'enum','required'=>true,'in'=>['open','closed','draft']]);
        $vApi->validate('tags',   ['type'=>'array','min_count'=>0,'max_count'=>10,'unique'=>true]);
        $vApi->validate('price',  ['type'=>'number','min'=>0,'max'=>100000,'step'=>0.01]);

        $results['unconsumed'] = $vApi->ensureConsumed();
        $results['clean']      = $vApi->getClean();
        $results['errors']     = $vApi->getErrors();
        $results['last_error'] = $vApi->getLastError();

        // Restore
        $_POST = $backupPOST;
    }
    $results['api_method'] = $apiMethod;
}
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>RequestValidator – Test (GET / POST / FILES / API)</title>
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
.box{border:1px solid #eee;border-radius:10px;margin-bottom:14px;overflow:hidden}
.box summary{list-style:none}
.box summary::-webkit-details-marker{display:none}
.box__title{cursor:pointer;user-select:none;padding:10px 12px;border-bottom:1px solid #eee;font-weight:700;background:#fafafa}
.box__body{padding:12px}
.box__title::before{content:"▸";display:inline-block;margin-right:.5rem;transform:translateY(-1px) rotate(0deg);transition:transform .15s ease}
.box[open] .box__title::before{transform:translateY(-1px) rotate(90deg)}
.ok{color:#0a7a2f}.errors{color:#b00020}
pre{white-space:pre-wrap}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
</style>
</head>
<body>
<h1>RequestValidator – Test (GET / POST / FILES / API)</h1>

<div class="tabs">
  <?php
    $tabs = ['GET'=>'GET','POST'=>'POST','FILES'=>'FILES','API'=>'API'];
    foreach ($tabs as $k=>$label) {
        $active = ($mode===$k)?'active':'';
        echo "<a class='{$active}' href='?mode={$k}'>".h($label)."</a>";
    }
  ?>
</div>

<div class="wrap">
  <div>
    <?php if($mode==='GET'): ?>
      <form method="get">
        <input type="hidden" name="mode" value="GET">
        <input type="hidden" name="submit_get" value="1">
        <fieldset>
          <legend>GET</legend>
          <label>Suchstring * <input type="text" name="q" value="<?= fieldValue('q','StandardSuche') ?>"></label>
          <div class="grid2">
            <label>Seite (≥1) <input type="number" name="page" min="1" value="<?= fieldValue('page','1') ?>"></label>
            <label>E-Mail <input type="email" name="email" value="<?= fieldValue('email','demo@example.com') ?>"></label>
          </div>
        </fieldset>
        <button type="submit">GET prüfen</button>
      </form>

    <?php elseif($mode==='POST'): ?>
      <form method="post" action="?mode=POST" novalidate>
        <input type="hidden" name="form_id" value="post">
        <fieldset>
          <legend>POST</legend>
          <label>Name * <input type="text" name="name" value="<?= fieldValue('name','Max Mustermann') ?>"></label>
          <label><input type="checkbox" name="agree" <?= isset($_POST['agree'])?'checked':'checked'; ?>> AGB akzeptieren *</label>
          <label>Rolle *
            <span class="small">
              <?php $r=$_POST['role']??'user'; foreach(['user','editor','admin'] as $x){$c=$r===$x?'checked':''; echo "<label class='small'><input type='radio' name='role' value='".h($x)."' $c> ".h($x)."</label> ";} ?>
            </span>
          </label>
          <label>Tags
            <select name="tags[]" multiple size="5">
              <?php $sel=$_POST['tags']??['php']; foreach(['php','js','css','html','sql','docker'] as $t){$s=in_array($t,(array)$sel,true)?'selected':''; echo "<option value='".h($t)."' $s>".h(strtoupper($t))."</option>";} ?>
            </select>
          </label>
          <div class="grid2">
            <label>Preis <input type="number" step="0.01" name="price" value="<?= fieldValue('price','19.99') ?>"></label>
            <label>Webseite <input type="url" name="website" value="<?= fieldValue('website','https://example.org') ?>"></label>
          </div>
          <div class="grid2">
            <label>Passwort * <input type="password" name="password" value="DemoPass1"></label>
            <label>Passwort bestätigen * <input type="password" name="password_confirm" value="DemoPass1"></label>
          </div>
        </fieldset>
        <button type="submit">POST prüfen</button>
      </form>

    <?php elseif($mode==='FILES'): ?>
      <form method="post" action="?mode=FILES" enctype="multipart/form-data" novalidate>
        <input type="hidden" name="form_id" value="files">
        <fieldset>
          <legend>FILES</legend>
          <label>Avatar * <input type="file" name="avatar" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" required></label>
          <label>Attachments (0–5) <input type="file" name="attachments[]" accept=".jpg,.jpeg,.png,.gif,.pdf,image/jpeg,image/png,image/gif,application/pdf" multiple></label>
        </fieldset>
        <button type="submit">FILES prüfen & verschieben</button>
      </form>

    <?php else: /* API wie die anderen */ ?>
      <form method="post" action="?mode=API" novalidate>
        <input type="hidden" name="form_id" value="api">
        <fieldset>
          <legend>API (Payload als JSON)</legend>
          <div class="grid2">
            <label>API-Methode (Anzeige)
              <select name="_api_method">
                <?php foreach (['PUT','PATCH','DELETE','OPTIONS','HEAD','TRACE','CONNECT'] as $m): ?>
                  <option <?= (($_POST['_api_method'] ?? '')===$m)?'selected':''; ?>><?= $m ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label class="small">Beispiel
              <input type="text" value='{"title":"Test","status":"open","tags":["a","b"],"price":12.34}' readonly>
            </label>
          </div>
          <label>JSON-Body
            <textarea name="_api_body" rows="10"><?= h($_POST['_api_body'] ?? '{"title":"Test","status":"open","tags":["a","b"],"price":12.34}') ?></textarea>
          </label>
        </fieldset>
        <button type="submit">API prüfen</button>
      </form>
    <?php endif; ?>
  </div>

  <div>
    <?php
      $hasErrors = !empty(array_filter($results['errors']));
      $subtitle = ($mode==='API' && $results['api_method']) ? ' ('.$results['api_method'].')' : '';

      if ($mode==='GET' && isset($_GET['submit_get'])) {
          echo box('GET → Clean', pre($results['clean']), '', false);
          echo box('GET → Errors', $hasErrors ? pre($results['errors']) : '<p class="ok">Keine Fehler ✅</p>', 'errors', $hasErrors);
          if (!empty($results['unconsumed'])) echo box('GET → Unconsumed', pre($results['unconsumed']));
          if (!empty($results['last_error'])) echo box('GET → Last Error', '<p class="errors">'.h($results['last_error']).'</p>', '', true);
      }
      if ($mode==='POST' && $formId==='post') {
          echo box('POST → Clean', pre($results['clean']));
          echo box('POST → Errors', $hasErrors ? pre($results['errors']) : '<p class="ok">Keine Fehler ✅</p>', 'errors', $hasErrors);
          if (!empty($results['unconsumed'])) echo box('POST → Unconsumed', pre($results['unconsumed']));
          if (!empty($results['last_error'])) echo box('POST → Last Error', '<p class="errors">'.h($results['last_error']).'</p>', '', true);
      }
      if ($mode==='FILES' && $formId==='files') {
          echo box('FILES → Clean', pre($results['clean']));
          echo box('FILES → Errors', $hasErrors ? pre($results['errors']) : '<p class="ok">Keine Fehler ✅</p>', 'errors', $hasErrors);
          if (!empty($results['unconsumed'])) echo box('FILES → Unconsumed', pre($results['unconsumed']));
          if (!empty($results['last_error'])) echo box('FILES → Last Error', '<p class="errors">'.h($results['last_error']).'</p>', '', true);
          if (!$hasErrors && !empty($results['moved'])) {
              $rows=''; foreach($results['moved'] as $r){
                  $rows.="<tr><td>".(!empty($r['ok'])?'✅':'❌')."</td><td>".h((string)($r['client_name']??''))."</td><td><code>".h((string)($r['source']??''))."</code></td><td><code>".h((string)($r['target']??''))."</code></td><td>".h((string)($r['error']??''))."</td></tr>";
              }
              $table="<table border='1' cellpadding='6' cellspacing='0'><thead><tr><th>OK</th><th>Client</th><th>Quelle</th><th>Ziel</th><th>Error</th></tr></thead><tbody>{$rows}</tbody></table>";
              echo box('FILES → moveUploaded()', $table, '', true);
          }
      }
      if ($mode==='API' && $formId==='api') {
          echo box('API'.$subtitle.' → Clean', pre($results['clean']));
          echo box('API'.$subtitle.' → Errors', $hasErrors ? pre($results['errors']) : '<p class="ok">Keine Fehler ✅</p>', 'errors', $hasErrors);
          if (!empty($results['unconsumed'])) echo box('API'.$subtitle.' → Unconsumed', pre($results['unconsumed']));
          if (!empty($results['last_error'])) echo box('API'.$subtitle.' → Last Error', '<p class="errors">'.h($results['last_error']).'</p>', '', true);
      }
      if (!in_array($mode, ['GET','POST','FILES','API'], true)) {
          echo box('Hinweis', '<p>Unbekannter Modus – wähle oben einen Tab.</p>', '', true);
      }
    ?>
  </div>
</div>
</body>
</html>
