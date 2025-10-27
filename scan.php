<?php
/**
 * scanner parth write
 * dz
 */

declare(strict_types=1);
mb_internal_encoding('UTF-8');
@ini_set('memory_limit', '512M');
@set_time_limit(300);

/* ===== Utils ===== */
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function normPath(string $p): string { $p = rtrim($p, "/"); return $p === '' ? '/' : $p; }
function startsWith(string $haystack, string $needle): bool { return strncmp($haystack, $needle, strlen($needle)) === 0; }
function isExcluded(string $path, array $excludes): bool {
    $rp = @realpath($path) ?: $path;
    foreach ($excludes as $ex) {
        $ex = trim($ex); if ($ex === '') continue;
        $rex = @realpath($ex) ?: $ex;
        if ($rp === $rex || startsWith($rp.'/', rtrim($rex,'/').'/')) return true;
    }
    return false;
}

/**
 * Verifikasi ketat: buat file eksklusif, tulis, hapus.
 * Return: [bool $ok, string $reason]
 */
function canWriteStrict(string $dir): array {
    $name = $dir . DIRECTORY_SEPARATOR . '.wscan_' . bin2hex(random_bytes(6));
    $h = @fopen($name, 'xb'); // exclusive create
    if ($h === false) {
        $err = error_get_last();
        return [false, 'create-fail'.(!empty($err['message']) ? ': '.preg_replace('/\s+/', ' ', $err['message']) : '')];
    }
    $w = @fwrite($h, "probe");
    @fclose($h);
    if ($w === false) {
        @unlink($name);
        $err = error_get_last();
        return [false, 'write-fail'.(!empty($err['message']) ? ': '.preg_replace('/\s+/', ' ', $err['message']) : '')];
    }
    $rm = @unlink($name);
    return [true, $rm ? 'ok' : 'cleanup-fail'];
}

/**
 * Scan BFS direktori
 */
function scanWriteable(string $root, bool $verify, int $maxDepth, array $excludes): array {
    $root = normPath($root);
    $results = [];
    $method  = $verify ? 'verify' : 'quick';

    $queue = new SplQueue();
    $queue->enqueue([$root, 0]);
    $visited = [];

    while (!$queue->isEmpty()) {
        [$dir, $depth] = $queue->dequeue();
        $real = @realpath($dir) ?: $dir;
        if (isset($visited[$real])) continue;
        $visited[$real] = true;

        if (!@is_dir($real) || !@is_readable($real)) continue;
        if (isExcluded($real, $excludes)) continue;

        if ($verify) {
            [$ok, $reason] = canWriteStrict($real);
            if ($ok) $results[] = ['path'=>$real, 'method'=>$method, 'result'=>'YES', 'reason'=>$reason];
            else     $results[] = ['path'=>$real, 'method'=>$method, 'result'=>'NO',  'reason'=>$reason];
        } else {
            if (@is_writable($real)) $results[] = ['path'=>$real, 'method'=>$method, 'result'=>'MAYBE', 'reason'=>'is_writable'];
        }

        if ($depth < $maxDepth) {
            $dh = @opendir($real);
            if ($dh) {
                while (($entry = readdir($dh)) !== false) {
                    if ($entry === '.' || $entry === '..') continue;
                    $child = $real . DIRECTORY_SEPARATOR . $entry;
                    if (@is_dir($child) && !@is_link($child)) $queue->enqueue([$child, $depth + 1]);
                }
                @closedir($dh);
            }
        }
    }
    return $results;
}

/* ===== Defaults & Input ===== */
$defaultRoot = getenv('HOME') ?: ($_SERVER['DOCUMENT_ROOT'] ?? getcwd());
$defaultRoot = $defaultRoot ? normPath($defaultRoot) : '/';

$preset    = $_POST['preset']   ?? 'IncludeDev';
$extraEx   = isset($_POST['excludes']) ? trim((string)$_POST['excludes']) : '';
$root      = isset($_POST['root']) ? trim((string)$_POST['root']) : $defaultRoot;
$maxDepth  = isset($_POST['max_depth']) ? max(0, (int)$_POST['max_depth']) : 6;
$verify    = isset($_POST['verify']) ? (bool)$_POST['verify'] : true;
$onlyYes   = isset($_POST['only_yes']) ? (bool)$_POST['only_yes'] : false;
$pathsOnly = isset($_POST['paths_only']) ? (bool)$_POST['paths_only'] : false;
$useCRLF   = isset($_POST['use_crlf']) ? (bool)$_POST['use_crlf'] : false;
$doScan    = isset($_POST['do_scan']);

switch ($preset) {
    case 'Safe':       $excludes = ['/proc','/sys','/lost+found']; break;
    case 'IncludeDev': $excludes = ['/proc','/sys','/lost+found']; break; // /dev ikut
    case 'Everything': $excludes = []; break;
    default:           $excludes = ['/proc','/sys','/lost+found'];
}
if ($extraEx !== '') {
    foreach (explode(',', $extraEx) as $x) { $x = trim($x); if ($x !== '') $excludes[] = $x; }
}
if ($preset === 'Everything') $verify = true;

/* ===== Scan ===== */
$rows = [];
$paths_for_copy = [];
if ($doScan) {
    $rowsAll = scanWriteable($root, $verify, $maxDepth, $excludes);
    $rows = $onlyYes ? array_values(array_filter($rowsAll, fn($r)=>($r['result']??'')==='YES')) : $rowsAll;

    if (count($rows) > 20000) $rows = array_slice($rows, 0, 20000);

    // Array path untuk copy/preview (rapi & unik & terurut)
    $paths_for_copy = array_map(fn($r)=>$r['path'], $rows);
    $paths_for_copy = array_values(array_unique($paths_for_copy));
    sort($paths_for_copy, SORT_NATURAL | SORT_FLAG_CASE);

    $stats = [
        'total_scanned' => count($rowsAll),
        'yes'   => count(array_filter($rowsAll, fn($r)=>($r['result']??'')==='YES')),
        'maybe' => count(array_filter($rowsAll, fn($r)=>($r['result']??'')==='MAYBE')),
        'no'    => count(array_filter($rowsAll, fn($r)=>($r['result']??'')==='NO')),
        'displayed' => count($rows),
        'filtered'  => ($onlyYes ? 'YES only' : 'none') . ($pathsOnly ? ' + paths-only' : '') . ($useCRLF ? ' + CRLF' : ''),
        'preset'    => $preset,
        'verify'    => $verify ? 'strict' : 'quick'
    ];
} else {
    $stats = null;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Write Scanner</title>
<style>
  :root{--bg:#0b0d12;--card:#121622;--muted:#9aa6b2;--line:#23283a;--text:#e8eef6;--accent:#7de8ff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,Segoe UI,Roboto,Inter,sans-serif}
  .wrap{max-width:1100px;margin:24px auto;padding:0 16px}
  .title{font-size:20px;margin:0 0 16px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:16px}
  label{display:block;margin:8px 0 6px;color:var(--muted)}
  input[type=text],input[type=number],textarea,select{
    width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:#0e1220;color:var(--text)
  }
  textarea{
    font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
    white-space: pre;
  }
  .row{display:grid;gap:12px}
  @media(min-width:980px){.row{grid-template-columns: 1.3fr 140px 1fr 1fr}}
  .muted{color:var(--muted);font-size:12px}
  .btn{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border:1px solid var(--line);border-radius:10px;background:#121a2e;color:var(--text);cursor:pointer}
  .btn:hover{border-color:#2c3550}
  .checkbox{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:8px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{border-bottom:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
  th{position:sticky;top:0;background:#141a2b}
  .tag{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid var(--line);font-size:12px}
  .ok{color:#70e27b}.maybe{color:#ffd666}.no{color:#ff8080}
  .grid1{display:grid;gap:12px;grid-template-columns:1fr;} /* satu kolom */
  .copy{float:right}
  .stats{display:flex;gap:10px;flex-wrap:wrap;margin:8px 0}
  .pill{border:1px solid var(--line);border-radius:999px;padding:4px 10px}
  .stack{display:flex;flex-direction:column;gap:6px}
  .help{margin-top:4px}
</style>
</head>
<body>
<div class="wrap">
  <h1 class="title">🔎 Write Scanner</h1>

  <form method="post" class="card">
    <div class="row">
      <div class="stack">
        <label>Root folder</label>
        <input type="text" name="root" value="<?=h($root)?>" placeholder="/ (hati-hati, bisa lama)">
        <div class="muted help">Contoh cepat: <code><?=h($defaultRoot)?></code> atau <code>/</code> untuk seluruh sistem.</div>
      </div>

      <div class="stack">
        <label>Maks. kedalaman</label>
        <input type="number" name="max_depth" min="0" max="64" value="<?= (int)$maxDepth ?>">
        <div class="muted help">0 = hanya root. Besar = lebih lama.</div>
      </div>

      <div class="stack">
        <label>Preset Excludes</label>
        <select name="preset">
          <option value="Safe"      <?= $preset==='Safe'?'selected':'' ?>>Safe (exclude /proc, /sys, /lost+found)</option>
          <option value="IncludeDev"<?= $preset==='IncludeDev'?'selected':'' ?>>Include /dev (scan /dev & /dev/shm)</option>
          <option value="Everything"<?= $preset==='Everything'?'selected':'' ?>>Everything (tanpa exclude sama sekali)</option>
        </select>
        <div class="muted help">Pilih <b>Include /dev</b> agar <code>/dev</code> ikut discan. <b>Everything</b> memaksa verifikasi akurat.</div>
      </div>

      <div class="stack">
        <label>Exclude tambahan (opsional)</label>
        <input type="text" name="excludes" value="<?= h($extraEx) ?>" placeholder="/tmp,/var/tmp">
        <div class="muted help">Pisahkan koma. Ditambahkan di atas preset.</div>
      </div>
    </div>

    <div class="checkbox">
      <label><input type="checkbox" name="verify" value="1" <?= $verify ? 'checked' : '' ?>> Verifikasi nyata (buat & hapus file temp)</label>
      <label><input type="checkbox" name="only_yes" value="1" <?= $onlyYes ? 'checked' : '' ?>> Tampilkan hanya <strong>YES</strong></label>
      <label><input type="checkbox" name="paths_only" value="1" <?= $pathsOnly ? 'checked' : '' ?>> Salin <strong>path saja</strong> (satu per baris, terurut)</label>
      <label><input type="checkbox" name="use_crlf" value="1" <?= $useCRLF ? 'checked' : '' ?>> Gunakan <strong>CRLF (Windows)</strong></label>
    </div>

    <div style="margin-top:12px">
      <button class="btn" type="submit" name="do_scan" value="1">▶️ Jalankan Scan</button>
      <span class="muted">Untuk sistem besar, mulai dari kedalaman kecil dulu.</span>
    </div>
  </form>

  <?php if ($doScan): ?>
    <div class="card">
      <strong>Ringkasan</strong>
      <div class="stats">
        <span class="pill">Preset: <?= h($stats['preset']) ?></span>
        <span class="pill">Mode: <?= h($stats['verify']) ?></span>
        <span class="pill">Total dipindai: <?= (int)$stats['total_scanned'] ?></span>
        <span class="pill ok">YES: <?= (int)$stats['yes'] ?></span>
        <span class="pill maybe">MAYBE: <?= (int)$stats['maybe'] ?></span>
        <span class="pill no">NO: <?= (int)$stats['no'] ?></span>
        <span class="pill">Ditampilkan: <?= (int)$stats['displayed'] ?> (filter: <?= h($stats['filtered']) ?>)</span>
      </div>
    </div>

    <!-- Kotak teks di atas -->
    <div class="card">
      <div>
        <strong>Hasil (<?=count($rows)?> baris)</strong>
        <button class="btn copy" type="button" onclick="copyPaths()">📋 Copy teks</button>
      </div>
      <div class="muted" style="margin:6px 0 12px">Pratinjau di bawah mengikuti preset/filter. Tombol copy membangun baris dari array path (bukan dari server) agar rapi.</div>

      <!-- TEXTAREA DIISI OLEH JS (bukan dari PHP) -->
      <textarea id="textout" rows="12" readonly wrap="off"></textarea>

      <!-- Data untuk JS (array path & flags) -->
      <script id="paths-data" type="application/json"><?=json_encode($paths_for_copy, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)?></script>
      <script id="copy-flags" type="application/json"><?=json_encode(['paths_only'=>$pathsOnly,'use_crlf'=>$useCRLF], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)?></script>
    </div>

    <!-- Tabel detail di bawah -->
    <div class="grid1">
      <div class="card">
        <strong>Tabel detail</strong>
        <div class="muted" style="margin:6px 0 12px">
          <span class="tag ok">YES</span>
          <span class="tag maybe">MAYBE</span>
          <span class="tag no">NO</span>
        </div>
        <div style="max-height:420px;overflow:auto;border:1px solid var(--line);border-radius:10px">
          <table>
            <thead><tr><th>Path</th><th>Method</th><th>Result</th><th>Reason</th></tr></thead>
            <tbody>
              <?php foreach ($rows as $r): ?>
                <tr>
                  <td><?=h($r['path'])?></td>
                  <td><code><?=h($r['method'])?></code></td>
                  <td>
                    <?php if ($r['result']==='YES'): ?>
                      <span class="ok">YES</span>
                    <?php elseif ($r['result']==='MAYBE'): ?>
                      <span class="maybe">MAYBE</span>
                    <?php else: ?>
                      <span class="no">NO</span>
                    <?php endif; ?>
                  </td>
                  <td><?=h($r['reason'] ?? '')?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  <?php endif; ?>

  <div class="card" style="opacity:.9">
    <strong>Catatan</strong>
    <ul>
      <li>Centang <b>CRLF (Windows)</b> bila target editor mengharuskan CRLF.</li>
    </ul>
  </div>
</div>

<script>
/* Hydrate preview textarea dari array path (LF untuk tampilan rapi di browser) */
(function hydratePreview(){
  const arrEl = document.getElementById('paths-data');
  const ta    = document.getElementById('textout');
  if (!arrEl || !ta) return;
  let paths = [];
  try { paths = JSON.parse(arrEl.textContent || '[]'); } catch(e){ paths=[]; }
  const LF = String.fromCharCode(10);
  ta.value = (paths || []).join(LF) + (paths.length ? LF : '');
})();

/* Copy multi-baris bersih ke clipboard (pakai Blob text/plain agar newline tidak dimutilasi) */
async function copyPaths(){
  const arrEl  = document.getElementById('paths-data');
  const flagEl = document.getElementById('copy-flags');
  const ta     = document.getElementById('textout');

  let paths = [], flags = {paths_only:false, use_crlf:false};
  try { paths = JSON.parse(arrEl?.textContent || '[]'); } catch(e){}
  try { flags = Object.assign(flags, JSON.parse(flagEl?.textContent || '{}')); } catch(e){}

  const LF = String.fromCharCode(10);
  const CR = String.fromCharCode(13);
  const SEP = flags.use_crlf ? (CR + LF) : LF;

  const content = (paths || []).join(SEP) + (paths.length ? SEP : '');

  try {
    if (navigator.clipboard && window.ClipboardItem) {
      const blob = new Blob([content], { type: 'text/plain' });
      await navigator.clipboard.write([new ClipboardItem({ 'text/plain': blob })]);
    } else if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(content);
    } else {
      fallbackCopy(ta, content);
    }
  } catch (e) {
    fallbackCopy(ta, content);
  }

  // Sinkronkan preview (LF untuk tampilan)
  ta.value = (paths || []).join(LF) + (paths.length ? LF : '');
}

function fallbackCopy(ta, text){
  const prev = ta.value;
  ta.value = text;
  ta.focus();
  ta.select();
  try { document.execCommand('copy'); } catch(e) {}
  // Kembalikan preview agar tetap rapi (LF)
  const LF = String.fromCharCode(10);
  ta.value = prev.replace(/\r\n/g, LF);
}
</script>

</body>
</html>