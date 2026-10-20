<?php
declare(strict_types=1);

ini_set('session.cookie_httponly', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_samesite', 'Strict');

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: no-referrer');

define('CHAPAR_STORAGE_DIR', __DIR__ . '/chapar_storage');
define('CHAPAR_UPLOAD_DIR', 'uploads');
define('CHAPAR_GUARD_HEADER', "<?php http_response_code(403); exit; ?>\n");
define('CHAPAR_GUARD_LEN', strlen(CHAPAR_GUARD_HEADER));

final class ChaparSession
{
    private static bool $started = false;

    public static function bootReadOnly(): array
    {
        if (!self::$started && session_status() === PHP_SESSION_NONE) {
            session_start();
            self::$started = true;
        }
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        $snapshot = $_SESSION;
        session_write_close();
        return $snapshot;
    }

    public static function write(callable $mutator): array
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        $mutator($_SESSION);
        $snapshot = $_SESSION;
        session_write_close();
        return $snapshot;
    }

    public static function destroy(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $_SESSION = [];
        session_destroy();
        session_write_close();
    }
}

final class ChaparStorage
{
    private static bool $envVerified = false;

    public static function ensureEnvironment(): void
    {
        if (self::$envVerified) {
            return;
        }
        if (!is_dir(CHAPAR_STORAGE_DIR)) {
            mkdir(CHAPAR_STORAGE_DIR, 0750, true);
        }
        $htStorage = CHAPAR_STORAGE_DIR . '/.htaccess';
        if (!is_file($htStorage)) {
            file_put_contents(
                $htStorage,
                "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n"
            );
        }
        $idxStorage = CHAPAR_STORAGE_DIR . '/index.html';
        if (!is_file($idxStorage)) {
            file_put_contents($idxStorage, '');
        }

        $uploadAbs = __DIR__ . '/' . CHAPAR_UPLOAD_DIR;
        if (!is_dir($uploadAbs . '/npvt')) {
            mkdir($uploadAbs . '/npvt', 0755, true);
        }
        $htUpload = $uploadAbs . '/.htaccess';
        if (!is_file($htUpload)) {
            $rules = "<FilesMatch \"\\.(php|php5|php7|php8|phtml|phar|pl|py|cgi|sh|asp|aspx|jsp|htm|html|shtml|svg)$\">\n"
                   . "  <IfModule mod_authz_core.c>\n    Require all denied\n  </IfModule>\n"
                   . "  <IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n  </IfModule>\n"
                   . "</FilesMatch>\nOptions -Indexes -ExecCGI\n";
            file_put_contents($htUpload, $rules);
        }
        self::$envVerified = true;
    }

    private static function shardPath(string $shard): string
    {
        $clean = preg_replace('/[^a-zA-Z0-9_\-]/', '', $shard);
        return CHAPAR_STORAGE_DIR . '/' . $clean . '.dat.php';
    }

    public static function readShard(string $shard, callable $defaultFactory): array
    {
        self::ensureEnvironment();
        $path = self::shardPath($shard);
        if (!is_file($path)) {
            return self::mutateShard($shard, $defaultFactory, fn(array &$d) => null)['state'];
        }

        $fp = fopen($path, 'rb');
        if ($fp === false) {
            return $defaultFactory();
        }

        try {
            if (!flock($fp, LOCK_SH)) {
                return $defaultFactory();
            }
            $raw = stream_get_contents($fp);
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }

        if (!is_string($raw) || strlen($raw) <= CHAPAR_GUARD_LEN) {
            return $defaultFactory();
        }

        $decoded = json_decode(substr($raw, CHAPAR_GUARD_LEN), true);
        return is_array($decoded) ? $decoded : $defaultFactory();
    }

    public static function mutateShard(string $shard, callable $defaultFactory, callable $mutator): array
    {
        self::ensureEnvironment();
        $path = self::shardPath($shard);
        $fp = fopen($path, 'c+b');
        if ($fp === false) {
            throw new RuntimeException('Storage I/O initialization failed: ' . $shard);
        }

        try {
            if (!flock($fp, LOCK_EX)) {
                throw new RuntimeException('Storage lock acquisition failed: ' . $shard);
            }

            rewind($fp);
            $raw = stream_get_contents($fp);
            $state = null;

            if (is_string($raw) && strlen($raw) > CHAPAR_GUARD_LEN) {
                $state = json_decode(substr($raw, CHAPAR_GUARD_LEN), true);
            }
            if (!is_array($state)) {
                $state = $defaultFactory();
            }

            $dirty = true;
            $result = $mutator($state, $dirty);

            if ($dirty) {
                $payload = CHAPAR_GUARD_HEADER . json_encode(
                    $state,
                    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
                );
                ftruncate($fp, 0);
                rewind($fp);
                $written = fwrite($fp, $payload);
                if ($written === false || $written < strlen($payload)) {
                    throw new RuntimeException('Incomplete disk write on shard: ' . $shard);
                }
                fflush($fp);
            }

            return ['state' => $state, 'result' => $result];
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    public static function deleteTopicShard(int $topicId): void
    {
        $path = self::shardPath('topic_' . $topicId);
        if (is_file($path)) {
            @unlink($path);
        }
    }

    public static function defaultMeta(): array
    {
        $now = time();
        return [
            'config' => [
                'app_name'       => 'چاپار',
                'admin_username' => 'admin',
                'admin_hash'     => password_hash('chaparadmin', PASSWORD_DEFAULT),
                'ttl_hours'      => 72,
                'max_messages'   => 500,
                'chat_locked'    => false,
                'allow_uploads'  => true,
                'meta_version'   => 1,
            ],
            'seq' => [
                'user_id'  => 1,
                'msg_id'   => 0,
                'topic_id' => 1,
                'news_id'  => 0,
            ],
            'users' => [
                1 => [
                    'user_id'    => 1,
                    'username'   => 'admin',
                    'role'       => 'admin',
                    'ip_address' => '127.0.0.1',
                    'created_at' => $now,
                    'banned'     => false,
                ],
            ],
            'banned_ips' => [],
            'topics' => [
                1 => [
                    'id'         => 1,
                    'name'       => 'عمومی',
                    'created_by' => 1,
                    'created_at' => $now,
                    'max_msg_id' => 0,
                    'version'    => 1,
                    'msg_count'  => 0,
                ],
            ],
            'news' => [],
        ];
    }

    public static function defaultEphemeral(): array
    {
        return [
            'presence'   => [],
            'typing'     => [],
            'views'      => [],
            'rate_limit' => [],
        ];
    }

    public static function defaultTopic(): array
    {
        return [
            'messages' => [],
            'pinned'   => [],
        ];
    }

    public static function purgeAttachment(?array $att): void
    {
        if (empty($att['path'])) {
            return;
        }
        $baseDir = realpath(__DIR__ . '/' . CHAPAR_UPLOAD_DIR);
        $target = realpath(__DIR__ . '/' . ltrim((string)$att['path'], '/'));
        if ($baseDir !== false && $target !== false && strpos($target, $baseDir) === 0 && is_file($target)) {
            @unlink($target);
        }
    }

    public static function gcTopicMessages(array &$topicState, int $ttlHours, int $maxMessages): bool
    {
        $changed = false;
        $now = time();

        if ($ttlHours > 0) {
            $cutoff = $now - ($ttlHours * 3600);
            foreach ($topicState['messages'] as $id => $msg) {
                if (empty($msg['pinned']) && (int)($msg['created_at'] ?? 0) < $cutoff) {
                    self::purgeAttachment($msg['attachment'] ?? null);
                    unset($topicState['messages'][$id]);
                    $changed = true;
                }
            }
        }

        $count = count($topicState['messages']);
        if ($count > $maxMessages) {
            $toRemove = $count - $maxMessages;
            $removed = 0;
            foreach ($topicState['messages'] as $id => $msg) {
                if ($removed >= $toRemove) {
                    break;
                }
                if (empty($msg['pinned'])) {
                    self::purgeAttachment($msg['attachment'] ?? null);
                    unset($topicState['messages'][$id]);
                    $removed++;
                    $changed = true;
                }
            }
        }

        return $changed;
    }

    public static function checkRateLimit(array &$ephemeral, string $bucketKey, int $maxHits, int $windowSec): bool
    {
        $now = time();
        foreach ($ephemeral['rate_limit'] as $k => $entry) {
            if (($now - (int)($entry['start'] ?? 0)) > 120) {
                unset($ephemeral['rate_limit'][$k]);
            }
        }
        $slot = $ephemeral['rate_limit'][$bucketKey] ?? ['start' => $now, 'hits' => 0];
        if (($now - $slot['start']) >= $windowSec) {
            $slot = ['start' => $now, 'hits' => 1];
        } else {
            $slot['hits']++;
        }
        $ephemeral['rate_limit'][$bucketKey] = $slot;
        return $slot['hits'] <= $maxHits;
    }

    public static function computeDirectoryBytes(string $dir): int
    {
        if (!is_dir($dir)) {
            return 0;
        }
        $bytes = 0;
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iterator as $fileInfo) {
            if ($fileInfo->isFile()) {
                $bytes += $fileInfo->getSize();
            }
        }
        return $bytes;
    }
}

final class ChaparUploader
{
    public static function store(array $file, string $kind): ?array
    {
        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            return null;
        }
        $size = (int)($file['size'] ?? 0);
        if ($size <= 0 || $size > 15 * 1024 * 1024) {
            return null;
        }
        $tmpPath = (string)($file['tmp_name'] ?? '');
        if ($tmpPath === '' || !is_uploaded_file($tmpPath)) {
            return null;
        }

        $origName = basename((string)($file['name'] ?? 'file'));
        $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));

        if ($kind === 'image') {
            $allowedMap = [
                'image/jpeg' => 'jpg',
                'image/png'  => 'png',
                'image/gif'  => 'gif',
                'image/webp' => 'webp',
            ];
            $imgInfo = @getimagesize($tmpPath);
            if ($imgInfo === false || empty($imgInfo['mime']) || !isset($allowedMap[$imgInfo['mime']])) {
                return null;
            }
            if (($imgInfo[0] ?? 0) > 8000 || ($imgInfo[1] ?? 0) > 8000) {
                return null;
            }
            $canonicalExt = $allowedMap[$imgInfo['mime']];
            $fileName = bin2hex(random_bytes(12)) . '.' . $canonicalExt;
            $relPath = CHAPAR_UPLOAD_DIR . '/' . $fileName;
            if (move_uploaded_file($tmpPath, __DIR__ . '/' . $relPath)) {
                return [
                    'type' => 'image',
                    'path' => $relPath,
                    'name' => mb_substr($origName, 0, 80, 'UTF-8'),
                    'size' => $size,
                ];
            }
            return null;
        }

        if ($kind === 'npvt') {
            if ($ext !== 'npvt') {
                return null;
            }
            $head = (string)file_get_contents($tmpPath, false, null, 0, 256);
            if (stripos($head, '<?php') !== false || stripos($head, '<script') !== false) {
                return null;
            }
            $safeStem = preg_replace('/[^a-zA-Z0-9_\-]/', '_', pathinfo($origName, PATHINFO_FILENAME));
            $safeStem = substr($safeStem ?: 'config', 0, 32);
            $fileName = $safeStem . '_' . bin2hex(random_bytes(6)) . '.npvt';
            $relPath = CHAPAR_UPLOAD_DIR . '/npvt/' . $fileName;
            if (move_uploaded_file($tmpPath, __DIR__ . '/' . $relPath)) {
                return [
                    'type' => 'npvt',
                    'path' => $relPath,
                    'name' => mb_substr($origName, 0, 80, 'UTF-8'),
                    'size' => $size,
                ];
            }
            return null;
        }

        return null;
    }
}
function chaparClientIp(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function chaparJsonOut(array $payload, int $status = 200): never
{
    if ($status !== 200) {
        http_response_code($status);
    }
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function chaparVerifyCsrf(array $session): void
{
    $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($session['csrf_token']) || !hash_equals((string)$session['csrf_token'], (string)$token)) {
        chaparJsonOut(['success' => false, 'message' => 'نشست امنیتی منقضی شده است. صفحه را بازنشانی کنید.'], 403);
    }
}

function chaparProjectMessage(array $msg, array $users, array $topicViews): array
{
    $uid = (int)($msg['user_id'] ?? 0);
    $user = $users[$uid] ?? ['username' => 'کاربر', 'role' => 'user'];
    $msgId = (int)($msg['msg_id'] ?? 0);

    $seenCount = 0;
    foreach ($topicViews as $seenMsgId) {
        if ((int)$seenMsgId >= $msgId) {
            $seenCount++;
        }
    }

    $replySnap = $msg['reply_snap'] ?? null;
    $att = $msg['attachment'] ?? null;
    $attType = is_array($att) ? ($att['type'] ?? '') : '';

    return [
        'msg_id'          => $msgId,
        'topic_id'        => (int)($msg['topic_id'] ?? 1),
        'user_id'         => $uid,
        'username'        => (string)$user['username'],
        'is_admin'        => ($user['role'] ?? '') === 'admin',
        'content'         => (string)($msg['content'] ?? ''),
        'is_encrypted'    => !empty($msg['is_encrypted']),
        'created_at'      => (int)($msg['created_at'] ?? 0) * 1000,
        'edited_at'       => !empty($msg['edited_at']) ? (int)$msg['edited_at'] * 1000 : null,
        'pinned'          => !empty($msg['pinned']) ? 1 : 0,
        'reply_to'        => !empty($msg['reply_to']) ? (int)$msg['reply_to'] : null,
        'reply_username'  => is_array($replySnap) ? (string)($replySnap['username'] ?? '') : '',
        'reply_content'   => is_array($replySnap) ? (string)($replySnap['content'] ?? '') : '',
        'reply_encrypted' => is_array($replySnap) && !empty($replySnap['is_encrypted']),
        'reply_count'     => (int)($msg['reply_count'] ?? 0),
        'seen_count'      => $seenCount,
        'is_image'        => $attType === 'image',
        'image_path'      => $attType === 'image' ? (string)$att['path'] : '',
        'is_npvt'         => $attType === 'npvt',
        'npvt_path'       => $attType === 'npvt' ? (string)$att['path'] : '',
        'npvt_filename'   => $attType === 'npvt' ? (string)($att['name'] ?? basename((string)$att['path'])) : '',
    ];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = (string)$_POST['action'];
    $clientIp = chaparClientIp();

    if ($action === 'login') {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');

        $uLen = mb_strlen($username, 'UTF-8');
        if ($uLen < 2 || $uLen > 32) {
            chaparJsonOut(['success' => false, 'message' => 'نام کاربری باید بین ۲ تا ۳۲ کاراکتر باشد.']);
        }
        if (preg_match('/[<>"\'\\\\\/`]/u', $username)) {
            chaparJsonOut(['success' => false, 'message' => 'نام کاربری حاوی کاراکتر غیرمجاز است.']);
        }

        $rateAllowed = ChaparStorage::mutateShard(
            'ephemeral',
            [ChaparStorage::class, 'defaultEphemeral'],
            fn(array &$eph) => ChaparStorage::checkRateLimit($eph, 'login_' . $clientIp, 12, 60)
        )['result'];

        if (!$rateAllowed) {
            chaparJsonOut(['success' => false, 'message' => 'تعداد تلاش‌های ورود بیش از حد مجاز است. یک دقیقه صبر کنید.'], 429);
        }

        $tx = ChaparStorage::mutateShard(
            'meta',
            [ChaparStorage::class, 'defaultMeta'],
            function (array &$meta, bool &$dirty) use ($username, $password, $clientIp) {
                if (in_array($clientIp, $meta['banned_ips'] ?? [], true)) {
                    $dirty = false;
                    return ['success' => false, 'message' => 'دسترسی شبکه شما به این سرور مسدود شده است.'];
                }

                $adminName = (string)($meta['config']['admin_username'] ?? 'admin');
                $isAdminAttempt = (mb_strtolower($username, 'UTF-8') === mb_strtolower($adminName, 'UTF-8'));

                if ($isAdminAttempt) {
                    if ($password === '' || !password_verify($password, (string)($meta['config']['admin_hash'] ?? ''))) {
                        $dirty = false;
                        return [
                            'success'          => false,
                            'message'          => 'رمز عبور مدیریت معتبر نیست.',
                            'require_password' => true,
                        ];
                    }
                    $username = $adminName;
                }

                $matchedUid = null;
                foreach ($meta['users'] as $uid => $u) {
                    if (mb_strtolower((string)$u['username'], 'UTF-8') === mb_strtolower($username, 'UTF-8')) {
                        $matchedUid = (int)$uid;
                        break;
                    }
                }

                if ($matchedUid !== null) {
                    if (!empty($meta['users'][$matchedUid]['banned']) && !$isAdminAttempt) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'این حساب کاربری مسدود شده است.'];
                    }
                    $meta['users'][$matchedUid]['ip_address'] = $clientIp;
                    if ($isAdminAttempt) {
                        $meta['users'][$matchedUid]['role'] = 'admin';
                    }
                } else {
                    $matchedUid = ++$meta['seq']['user_id'];
                    $meta['users'][$matchedUid] = [
                        'user_id'    => $matchedUid,
                        'username'   => $username,
                        'role'       => $isAdminAttempt ? 'admin' : 'user',
                        'ip_address' => $clientIp,
                        'created_at' => time(),
                        'banned'     => false,
                    ];
                }

                return [
                    'success'  => true,
                    'user_id'  => $matchedUid,
                    'username' => (string)$meta['users'][$matchedUid]['username'],
                    'role'     => (string)$meta['users'][$matchedUid]['role'],
                ];
            }
        )['result'];

        if (!empty($tx['success'])) {
            $uid = (int)$tx['user_id'];
            ChaparStorage::mutateShard(
                'ephemeral',
                [ChaparStorage::class, 'defaultEphemeral'],
                function (array &$eph) use ($uid, $clientIp) {
                    $eph['presence'][$uid] = ['ts' => time(), 'ip' => $clientIp];
                }
            );
            $sess = ChaparSession::write(function (array &$s) use ($tx) {
                session_regenerate_id(true);
                $s['user_id'] = $tx['user_id'];
                $s['username'] = $tx['username'];
                $s['role'] = $tx['role'];
            });
            $tx['csrf_token'] = $sess['csrf_token'];
        }

        chaparJsonOut($tx);
    }

    if ($action === 'logout') {
        $sess = ChaparSession::bootReadOnly();
        if (!empty($sess['user_id'])) {
            $uid = (int)$sess['user_id'];
            ChaparStorage::mutateShard(
                'ephemeral',
                [ChaparStorage::class, 'defaultEphemeral'],
                function (array &$eph) use ($uid) {
                    unset($eph['presence'][$uid]);
                }
            );
        }
        ChaparSession::destroy();
        chaparJsonOut(['success' => true]);
    }

    $session = ChaparSession::bootReadOnly();
    if (empty($session['user_id'])) {
        chaparJsonOut(['success' => false, 'logged_out' => true, 'message' => 'نشست کاربری پایان یافته است.'], 401);
    }

    chaparVerifyCsrf($session);
    $currentUserId = (int)$session['user_id'];

    if ($action === 'sync') {
        $meta = ChaparStorage::readShard('meta', [ChaparStorage::class, 'defaultMeta']);
        $user = $meta['users'][$currentUserId] ?? null;

        if (!$user || (!empty($user['banned']) && ($user['role'] ?? '') !== 'admin') || in_array($clientIp, $meta['banned_ips'] ?? [], true)) {
            ChaparSession::destroy();
            chaparJsonOut(['success' => false, 'logged_out' => true], 403);
        }

        $reqTopicId = max(1, (int)($_POST['topic_id'] ?? 1));
        if (!isset($meta['topics'][$reqTopicId])) {
            $reqTopicId = (int)array_key_first($meta['topics']);
        }

        $clientLastId = max(0, (int)($_POST['last_id'] ?? 0));
        $clientTopicVer = (int)($_POST['topic_version'] ?? 0);
        $typingFlag = isset($_POST['is_typing']) ? (int)$_POST['is_typing'] : -1;

        $serverTopicMeta = $meta['topics'][$reqTopicId];
        $serverTopicVer = (int)($serverTopicMeta['version'] ?? 1);
        $serverMaxMsgId = (int)($serverTopicMeta['max_msg_id'] ?? 0);

        $ephResult = ChaparStorage::mutateShard(
            'ephemeral',
            [ChaparStorage::class, 'defaultEphemeral'],
            function (array &$eph) use ($currentUserId, $clientIp, $reqTopicId, $typingFlag, $serverMaxMsgId, $meta) {
                $now = time();
                $eph['presence'][$currentUserId] = ['ts' => $now, 'ip' => $clientIp];

                foreach ($eph['presence'] as $uid => $pData) {
                    if (($now - (int)($pData['ts'] ?? 0)) > 60 || !empty($meta['users'][$uid]['banned'])) {
                        unset($eph['presence'][$uid]);
                    }
                }

                $tKey = $reqTopicId . '_' . $currentUserId;
                if ($typingFlag === 1) {
                    $eph['typing'][$tKey] = $now;
                } elseif ($typingFlag === 0) {
                    unset($eph['typing'][$tKey]);
                }

                $typingUsers = [];
                foreach ($eph['typing'] as $k => $ts) {
                    if (($now - (int)$ts) > 5) {
                        unset($eph['typing'][$k]);
                        continue;
                    }
                    [$tPart, $uPart] = array_map('intval', explode('_', $k));
                    if ($tPart === $reqTopicId && $uPart !== $currentUserId && isset($meta['users'][$uPart])) {
                        $typingUsers[] = (string)$meta['users'][$uPart]['username'];
                    }
                }

                if ($serverMaxMsgId > 0) {
                    $prevSeen = (int)($eph['views'][$reqTopicId][$currentUserId] ?? 0);
                    if ($serverMaxMsgId > $prevSeen) {
                        $eph['views'][$reqTopicId][$currentUserId] = $serverMaxMsgId;
                    }
                }

                $onlineUsers = [];
                foreach ($eph['presence'] as $uid => $_) {
                    if (isset($meta['users'][$uid])) {
                        $onlineUsers[] = (string)$meta['users'][$uid]['username'];
                    }
                }
                sort($onlineUsers);

                return [
                    'online_users' => $onlineUsers,
                    'typing_users' => array_values(array_unique($typingUsers)),
                    'views'        => $eph['views'],
                ];
            }
        )['result'];

        $topicsOut = [];
        $unreadCounts = [];
        foreach ($meta['topics'] as $tid => $tInfo) {
            $topicsOut[] = [
                'id'         => (int)$tInfo['id'],
                'name'       => (string)$tInfo['name'],
                'created_at' => (int)$tInfo['created_at'],
            ];
            $seenId = (int)($ephResult['views'][$tid][$currentUserId] ?? 0);
            $maxId = (int)($tInfo['max_msg_id'] ?? 0);
            $unreadCounts[$tid] = ($tid !== $reqTopicId && $maxId > $seenId) ? min(99, $maxId - $seenId) : 0;
        }

        $topicChanged = ($clientTopicVer !== $serverTopicVer);
        $hasNewMessages = ($clientLastId < $serverMaxMsgId);
        $forceReload = ($clientTopicVer > 0 && $topicChanged);

        $messagesOut = [];
        $pinnedOut = null;

        if ($topicChanged || $hasNewMessages || $clientLastId === 0) {
            $topicData = ChaparStorage::readShard('topic_' . $reqTopicId, [ChaparStorage::class, 'defaultTopic']);
            $topicViews = $ephResult['views'][$reqTopicId] ?? [];

            if ($forceReload || $clientLastId === 0) {
                $slice = array_slice($topicData['messages'], -80, null, true);
            } else {
                $slice = [];
                foreach ($topicData['messages'] as $mId => $mRow) {
                    if ((int)$mId > $clientLastId) {
                        $slice[$mId] = $mRow;
                    }
                }
            }

            foreach ($slice as $mRow) {
                $messagesOut[] = chaparProjectMessage($mRow, $meta['users'], $topicViews);
            }

            $pinnedOut = [];
            foreach ($topicData['messages'] as $mRow) {
                if (!empty($mRow['pinned'])) {
                    $pinnedOut[] = chaparProjectMessage($mRow, $meta['users'], $topicViews);
                }
            }
            $pinnedOut = array_reverse($pinnedOut);
        }

        chaparJsonOut([
            'success'       => true,
            'topic_id'      => $reqTopicId,
            'topic_version' => $serverTopicVer,
            'reload_topic'  => $forceReload,
            'messages'      => $messagesOut,
            'pinned'        => $pinnedOut,
            'topics'        => $topicsOut,
            'unread_counts' => $unreadCounts,
            'online_count'  => count($ephResult['online_users']),
            'online_users'  => $ephResult['online_users'],
            'typing'        => $ephResult['typing_users'],
            'chat_locked'   => !empty($meta['config']['chat_locked']),
            'allow_uploads' => !empty($meta['config']['allow_uploads']),
        ]);
    }

    if ($action === 'send_message' || $action === 'upload_npvt') {
        $content = (string)($_POST['content'] ?? '');
        $topicId = max(1, (int)($_POST['topic_id'] ?? 1));
        $replyTo = !empty($_POST['reply_to']) ? (int)$_POST['reply_to'] : null;
        $isEncrypted = !empty($_POST['is_encrypted']);

        if (mb_strlen($content, 'UTF-8') > 16384) {
            chaparJsonOut(['success' => false, 'message' => 'حجم پیام بیش از حد مجاز است.']);
        }

        $rateOk = ChaparStorage::mutateShard(
            'ephemeral',
            [ChaparStorage::class, 'defaultEphemeral'],
            fn(array &$eph) => ChaparStorage::checkRateLimit($eph, 'msg_' . $currentUserId, 25, 30)
        )['result'];

        if (!$rateOk) {
            chaparJsonOut(['success' => false, 'message' => 'سرعت ارسال پیام بیش از حد مجاز است. چند ثانیه صبر کنید.'], 429);
        }

        $metaCheck = ChaparStorage::readShard('meta', [ChaparStorage::class, 'defaultMeta']);
        $user = $metaCheck['users'][$currentUserId] ?? null;
        if (!$user || (!empty($user['banned']) && ($user['role'] ?? '') !== 'admin')) {
            chaparJsonOut(['success' => false, 'message' => 'دسترسی شما مسدود است.'], 403);
        }
        $isAdmin = ($user['role'] ?? '') === 'admin';

        if (!empty($metaCheck['config']['chat_locked']) && !$isAdmin) {
            chaparJsonOut(['success' => false, 'message' => 'چت‌روم توسط مدیریت قفل شده است.']);
        }
        if (!isset($metaCheck['topics'][$topicId])) {
            chaparJsonOut(['success' => false, 'message' => 'تاپیک مورد نظر یافت نشد.']);
        }

        $attachment = null;
        if ($action === 'upload_npvt') {
            if (!$isAdmin) {
                chaparJsonOut(['success' => false, 'message' => 'فقط مدیر مجاز به آپلود فایل npvt است.'], 403);
            }
            if (empty($_FILES['npvt_file'])) {
                chaparJsonOut(['success' => false, 'message' => 'فایلی انتخاب نشده است.']);
            }
            $attachment = ChaparUploader::store($_FILES['npvt_file'], 'npvt');
            if (!$attachment) {
                chaparJsonOut(['success' => false, 'message' => 'فایل npvt نامعتبر است.']);
            }
        } elseif (!empty($_FILES['image']) && ($_FILES['image']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
            if (empty($metaCheck['config']['allow_uploads']) && !$isAdmin) {
                chaparJsonOut(['success' => false, 'message' => 'ارسال تصویر در حال حاضر غیرفعال است.']);
            }
            $attachment = ChaparUploader::store($_FILES['image'], 'image');
            if (!$attachment) {
                chaparJsonOut(['success' => false, 'message' => 'تصویر نامعتبر است یا حجم آن بیش از ۱۵ مگابایت است.']);
            }
        }

        if (trim($content) === '' && !$attachment) {
            chaparJsonOut(['success' => false, 'message' => 'پیام نمی‌تواند خالی باشد.']);
        }

        $alloc = ChaparStorage::mutateShard(
            'meta',
            [ChaparStorage::class, 'defaultMeta'],
            function (array &$meta) use ($topicId, $currentUserId, $clientIp) {
                $newMsgId = ++$meta['seq']['msg_id'];
                $meta['users'][$currentUserId]['ip_address'] = $clientIp;
                if (isset($meta['topics'][$topicId])) {
                    $meta['topics'][$topicId]['max_msg_id'] = $newMsgId;
                }
                return [
                    'msg_id'       => $newMsgId,
                    'ttl_hours'    => (int)($meta['config']['ttl_hours'] ?? 72),
                    'max_messages' => (int)($meta['config']['max_messages'] ?? 500),
                    'users'        => $meta['users'],
                ];
            }
        )['result'];

        $msgId = (int)$alloc['msg_id'];

        ChaparStorage::mutateShard(
            'topic_' . $topicId,
            [ChaparStorage::class, 'defaultTopic'],
            function (array &$tState) use ($msgId, $topicId, $currentUserId, $content, $isEncrypted, $replyTo, $attachment, $alloc) {
                ChaparStorage::gcTopicMessages($tState, $alloc['ttl_hours'], $alloc['max_messages']);

                $replySnap = null;
                $validReplyTo = null;
                if ($replyTo !== null && isset($tState['messages'][$replyTo])) {
                    $validReplyTo = $replyTo;
                    $parent = &$tState['messages'][$replyTo];
                    $parent['reply_count'] = (int)($parent['reply_count'] ?? 0) + 1;
                    $parentUid = (int)($parent['user_id'] ?? 0);
                    $replySnap = [
                        'username'     => (string)($alloc['users'][$parentUid]['username'] ?? 'کاربر'),
                        'content'      => (string)($parent['content'] ?? ''),
                        'is_encrypted' => !empty($parent['is_encrypted']),
                    ];
                }

                $tState['messages'][$msgId] = [
                    'msg_id'       => $msgId,
                    'topic_id'     => $topicId,
                    'user_id'      => $currentUserId,
                    'content'      => $content,
                    'is_encrypted' => $isEncrypted,
                    'reply_to'     => $validReplyTo,
                    'reply_snap'   => $replySnap,
                    'reply_count'  => 0,
                    'pinned'       => false,
                    'attachment'   => $attachment,
                    'created_at'   => time(),
                    'edited_at'    => null,
                ];
            }
        );

        ChaparStorage::mutateShard(
            'ephemeral',
            [ChaparStorage::class, 'defaultEphemeral'],
            function (array &$eph) use ($topicId, $currentUserId, $msgId) {
                $eph['views'][$topicId][$currentUserId] = $msgId;
                unset($eph['typing'][$topicId . '_' . $currentUserId]);
            }
        );

        chaparJsonOut(['success' => true, 'msg_id' => $msgId]);
    }

    if ($action === 'edit_message' || $action === 'delete_message' || $action === 'pin_message') {
        $msgId = (int)($_POST['msg_id'] ?? 0);
        $topicId = max(1, (int)($_POST['topic_id'] ?? 1));
        $meta = ChaparStorage::readShard('meta', [ChaparStorage::class, 'defaultMeta']);
        $isAdmin = (($meta['users'][$currentUserId]['role'] ?? '') === 'admin');

        if (!isset($meta['topics'][$topicId])) {
            chaparJsonOut(['success' => false, 'message' => 'تاپیک یافت نشد.']);
        }

        $opResult = ChaparStorage::mutateShard(
            'topic_' . $topicId,
            [ChaparStorage::class, 'defaultTopic'],
            function (array &$tState, bool &$dirty) use ($action, $msgId, $currentUserId, $isAdmin) {
                if (!isset($tState['messages'][$msgId])) {
                    $dirty = false;
                    return ['success' => false, 'message' => 'پیام مورد نظر یافت نشد.'];
                }
                $target = &$tState['messages'][$msgId];

                if ($action === 'edit_message') {
                    if ((int)$target['user_id'] !== $currentUserId && !$isAdmin) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'شما مجاز به ویرایش این پیام نیستید.'];
                    }
                    $newContent = (string)($_POST['content'] ?? '');
                    if (trim($newContent) === '' || mb_strlen($newContent, 'UTF-8') > 16384) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'متن ویرایش‌شده نامعتبر است.'];
                    }
                    $target['content'] = $newContent;
                    $target['is_encrypted'] = !empty($_POST['is_encrypted']);
                    $target['edited_at'] = time();
                    return ['success' => true];
                }

                if ($action === 'delete_message') {
                    if ((int)$target['user_id'] !== $currentUserId && !$isAdmin) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'شما مجاز به حذف این پیام نیستید.'];
                    }
                    $parentId = (int)($target['reply_to'] ?? 0);
                    if ($parentId > 0 && isset($tState['messages'][$parentId])) {
                        $tState['messages'][$parentId]['reply_count'] = max(0, (int)($tState['messages'][$parentId]['reply_count'] ?? 1) - 1);
                    }
                    ChaparStorage::purgeAttachment($target['attachment'] ?? null);
                    unset($tState['messages'][$msgId]);
                    return ['success' => true];
                }

                $newPin = empty($target['pinned']);
                $target['pinned'] = $newPin;
                return ['success' => true, 'pinned' => $newPin ? 1 : 0];
            }
        )['result'];

        if (!empty($opResult['success'])) {
            ChaparStorage::mutateShard(
                'meta',
                [ChaparStorage::class, 'defaultMeta'],
                function (array &$m) use ($topicId) {
                    if (isset($m['topics'][$topicId])) {
                        $m['topics'][$topicId]['version'] = (int)($m['topics'][$topicId]['version'] ?? 1) + 1;
                    }
                }
            );
        }

        chaparJsonOut($opResult);
    }

    if ($action === 'create_topic' || $action === 'delete_topic' || $action === 'delete_topic_messages') {
        $res = ChaparStorage::mutateShard(
            'meta',
            [ChaparStorage::class, 'defaultMeta'],
            function (array &$meta, bool &$dirty) use ($action, $currentUserId) {
                if (($meta['users'][$currentUserId]['role'] ?? '') !== 'admin') {
                    $dirty = false;
                    return ['success' => false, 'message' => 'فقط مدیر مجاز به تغییر ساختار تاپیک‌هاست.'];
                }

                if ($action === 'create_topic') {
                    $name = trim((string)($_POST['name'] ?? ''));
                    if ($name === '' || mb_strlen($name, 'UTF-8') > 45) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'نام تاپیک باید بین ۱ تا ۴۵ کاراکتر باشد.'];
                    }
                    $tid = ++$meta['seq']['topic_id'];
                    $meta['topics'][$tid] = [
                        'id'         => $tid,
                        'name'       => $name,
                        'created_by' => $currentUserId,
                        'created_at' => time(),
                        'max_msg_id' => 0,
                        'version'    => 1,
                    ];
                    return ['success' => true, 'topic_id' => $tid];
                }

                $tid = (int)($_POST['topic_id'] ?? 0);
                if (!isset($meta['topics'][$tid])) {
                    $dirty = false;
                    return ['success' => false, 'message' => 'تاپیک یافت نشد.'];
                }

                if ($action === 'delete_topic' && count($meta['topics']) <= 1) {
                    $dirty = false;
                    return ['success' => false, 'message' => 'حداقل یک تاپیک باید در سیستم باقی بماند.'];
                }

                $topicData = ChaparStorage::readShard('topic_' . $tid, [ChaparStorage::class, 'defaultTopic']);
                foreach ($topicData['messages'] as $m) {
                    ChaparStorage::purgeAttachment($m['attachment'] ?? null);
                }

                if ($action === 'delete_topic') {
                    unset($meta['topics'][$tid]);
                    ChaparStorage::deleteTopicShard($tid);
                } else {
                    ChaparStorage::mutateShard(
                        'topic_' . $tid,
                        [ChaparStorage::class, 'defaultTopic'],
                        function (array &$tState) {
                            $tState = ChaparStorage::defaultTopic();
                        }
                    );
                    $meta['topics'][$tid]['version'] = (int)($meta['topics'][$tid]['version'] ?? 1) + 1;
                    $meta['topics'][$tid]['max_msg_id'] = 0;
                }

                return ['success' => true];
            }
        )['result'];

        chaparJsonOut($res);
    }

    if ($action === 'get_news' || $action === 'add_news' || $action === 'delete_all_news' || $action === 'delete_news_item' || $action === 'add_reaction') {
        if ($action === 'get_news') {
            $meta = ChaparStorage::readShard('meta', [ChaparStorage::class, 'defaultMeta']);
            $list = [];
            foreach (array_reverse($meta['news'], true) as $item) {
                $reactions = $item['reactions'] ?? [];
                $counts = ['like' => 0, 'fire' => 0, 'dislike' => 0];
                foreach ($reactions as $rType) {
                    if (isset($counts[$rType])) {
                        $counts[$rType]++;
                    }
                }
                $list[] = [
                    'id'            => (int)$item['id'],
                    'content'       => (string)$item['content'],
                    'created_at'    => (int)$item['created_at'] * 1000,
                    'reactions'     => $counts,
                    'user_reaction' => $reactions[$currentUserId] ?? null,
                ];
            }
            chaparJsonOut(['success' => true, 'news' => $list]);
        }

        $res = ChaparStorage::mutateShard(
            'meta',
            [ChaparStorage::class, 'defaultMeta'],
            function (array &$meta, bool &$dirty) use ($action, $currentUserId) {
                $isAdmin = (($meta['users'][$currentUserId]['role'] ?? '') === 'admin');

                if ($action === 'add_news') {
                    if (!empty($meta['config']['chat_locked']) && !$isAdmin) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'در حالت قفل، ثبت خبر محدود است.'];
                    }
                    $content = trim((string)($_POST['content'] ?? ''));
                    if ($content === '' || mb_strlen($content, 'UTF-8') > 4000) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'متن خبر نامعتبر است.'];
                    }
                    $nid = ++$meta['seq']['news_id'];
                    $meta['news'][$nid] = [
                        'id'         => $nid,
                        'content'    => $content,
                        'author_id'  => $currentUserId,
                        'created_at' => time(),
                        'reactions'  => [],
                    ];
                    if (count($meta['news']) > 100) {
                        $firstKey = array_key_first($meta['news']);
                        if ($firstKey !== null) {
                            unset($meta['news'][$firstKey]);
                        }
                    }
                    return ['success' => true];
                }

                if ($action === 'delete_all_news') {
                    if (!$isAdmin) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'فقط مدیر مجاز به پاک‌سازی کامل اخبار است.'];
                    }
                    $meta['news'] = [];
                    return ['success' => true];
                }

                if ($action === 'delete_news_item') {
                    $nid = (int)($_POST['news_id'] ?? 0);
                    if (!isset($meta['news'][$nid])) {
                        $dirty = false;
                        return ['success' => false];
                    }
                    if (!$isAdmin && (int)($meta['news'][$nid]['author_id'] ?? 0) !== $currentUserId) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'عدم دسترسی.'];
                    }
                    unset($meta['news'][$nid]);
                    return ['success' => true];
                }

                if ($action === 'add_reaction') {
                    $nid = (int)($_POST['news_id'] ?? 0);
                    $rType = (string)($_POST['reaction'] ?? '');
                    if (!isset($meta['news'][$nid]) || !in_array($rType, ['like', 'fire', 'dislike'], true)) {
                        $dirty = false;
                        return ['success' => false];
                    }
                    $prev = $meta['news'][$nid]['reactions'][$currentUserId] ?? null;
                    if ($prev === $rType) {
                        unset($meta['news'][$nid]['reactions'][$currentUserId]);
                        $stateAct = 'removed';
                    } else {
                        $meta['news'][$nid]['reactions'][$currentUserId] = $rType;
                        $stateAct = 'added';
                    }
                    $counts = ['like' => 0, 'fire' => 0, 'dislike' => 0];
                    foreach ($meta['news'][$nid]['reactions'] as $val) {
                        if (isset($counts[$val])) {
                            $counts[$val]++;
                        }
                    }
                    return ['success' => true, 'action' => $stateAct, 'reaction' => $rType, 'counts' => $counts];
                }

                $dirty = false;
                return ['success' => false];
            }
        )['result'];

        chaparJsonOut($res);
    }

    if (strpos($action, 'admin_') === 0) {
        $metaRead = ChaparStorage::readShard('meta', [ChaparStorage::class, 'defaultMeta']);
        if (($metaRead['users'][$currentUserId]['role'] ?? '') !== 'admin') {
            chaparJsonOut(['success' => false, 'message' => 'دسترسی محدود به مدیر سیستم است.'], 403);
        }

        if ($action === 'admin_get_dashboard') {
            $eph = ChaparStorage::readShard('ephemeral', [ChaparStorage::class, 'defaultEphemeral']);
            $now = time();

            $totalMessages = 0;
            foreach ($metaRead['topics'] as $tid => $_) {
                $tData = ChaparStorage::readShard('topic_' . $tid, [ChaparStorage::class, 'defaultTopic']);
                $totalMessages += count($tData['messages']);
            }

            $usersOut = [];
            foreach ($metaRead['users'] as $uid => $u) {
                $pInfo = $eph['presence'][$uid] ?? null;
                $lastTs = $pInfo ? (int)$pInfo['ts'] : (int)($u['created_at'] ?? 0);
                $isOnline = $pInfo && (($now - (int)$pInfo['ts']) <= 60);
                $usersOut[] = [
                    'user_id'       => (int)$uid,
                    'username'      => (string)$u['username'],
                    'role'          => (string)($u['role'] ?? 'user'),
                    'ip_address'    => (string)($pInfo['ip'] ?? $u['ip_address'] ?? '-'),
                    'online'        => $isOnline,
                    'last_activity' => $lastTs * 1000,
                    'banned'        => !empty($u['banned']),
                ];
            }
            usort($usersOut, fn($a, $b) => ($b['online'] <=> $a['online']) ?: ($b['last_activity'] <=> $a['last_activity']));

            $storageBytes = ChaparStorage::computeDirectoryBytes(CHAPAR_STORAGE_DIR);
            $uploadBytes = ChaparStorage::computeDirectoryBytes(__DIR__ . '/' . CHAPAR_UPLOAD_DIR);

            chaparJsonOut([
                'success' => true,
                'stats'   => [
                    'total_messages' => $totalMessages,
                    'total_users'    => count($metaRead['users']),
                    'total_topics'   => count($metaRead['topics']),
                    'db_size_kb'     => round($storageBytes / 1024, 2),
                    'upload_size_kb' => round($uploadBytes / 1024, 2),
                ],
                'config' => [
                    'app_name'       => (string)($metaRead['config']['app_name'] ?? 'چاپار'),
                    'admin_username' => (string)($metaRead['config']['admin_username'] ?? 'admin'),
                    'ttl_hours'      => (int)($metaRead['config']['ttl_hours'] ?? 72),
                    'max_messages'   => (int)($metaRead['config']['max_messages'] ?? 500),
                    'chat_locked'    => !empty($metaRead['config']['chat_locked']),
                    'allow_uploads'  => !empty($metaRead['config']['allow_uploads']),
                ],
                'users'      => $usersOut,
                'banned_ips' => array_values($metaRead['banned_ips'] ?? []),
            ]);
        }

        $adminTx = ChaparStorage::mutateShard(
            'meta',
            [ChaparStorage::class, 'defaultMeta'],
            function (array &$meta, bool &$dirty) use ($action, $currentUserId) {
                if ($action === 'admin_save_config') {
                    $meta['config']['app_name'] = trim((string)($_POST['app_name'] ?? 'چاپار')) ?: 'چاپار';
                    $meta['config']['ttl_hours'] = max(0, (int)($_POST['ttl_hours'] ?? 72));
                    $meta['config']['max_messages'] = max(50, min(10000, (int)($_POST['max_messages'] ?? 500)));
                    $meta['config']['chat_locked'] = !empty($_POST['chat_locked']);
                    $meta['config']['allow_uploads'] = !empty($_POST['allow_uploads']);

                    $newAdminName = trim((string)($_POST['admin_username'] ?? ''));
                    if ($newAdminName !== '' && mb_strlen($newAdminName, 'UTF-8') >= 2) {
                        $meta['config']['admin_username'] = $newAdminName;
                        $meta['users'][$currentUserId]['username'] = $newAdminName;
                        ChaparSession::write(fn(array &$s) => $s['username'] = $newAdminName);
                    }

                    $newPass = (string)($_POST['admin_password'] ?? '');
                    if ($newPass !== '') {
                        if (mb_strlen($newPass, 'UTF-8') < 6) {
                            $dirty = false;
                            return ['success' => false, 'message' => 'رمز عبور مدیریت باید حداقل ۶ کاراکتر باشد.'];
                        }
                        $meta['config']['admin_hash'] = password_hash($newPass, PASSWORD_DEFAULT);
                    }
                    return ['success' => true, 'message' => 'پیکربندی چاپار ذخیره شد.'];
                }

                if ($action === 'admin_toggle_ban') {
                    $targetUid = (int)($_POST['target_user_id'] ?? 0);
                    if ($targetUid === $currentUserId || !isset($meta['users'][$targetUid])) {
                        $dirty = false;
                        return ['success' => false, 'message' => 'کاربر نامعتبر است.'];
                    }
                    $newBan = empty($meta['users'][$targetUid]['banned']);
                    $meta['users'][$targetUid]['banned'] = $newBan;
                    $ip = (string)($meta['users'][$targetUid]['ip_address'] ?? '');
                    if ($ip !== '' && $ip !== '127.0.0.1') {
                        if ($newBan && !in_array($ip, $meta['banned_ips'], true)) {
                            $meta['banned_ips'][] = $ip;
                        } elseif (!$newBan) {
                            $meta['banned_ips'] = array_values(array_diff($meta['banned_ips'], [$ip]));
                        }
                    }
                    return ['success' => true, 'banned' => $newBan];
                }

                if ($action === 'admin_unban_ip') {
                    $ip = trim((string)($_POST['ip'] ?? ''));
                    $meta['banned_ips'] = array_values(array_diff($meta['banned_ips'] ?? [], [$ip]));
                    return ['success' => true];
                }

                if ($action === 'admin_purge_all') {
                    foreach ($meta['topics'] as $tid => $_) {
                        $tData = ChaparStorage::readShard('topic_' . $tid, [ChaparStorage::class, 'defaultTopic']);
                        foreach ($tData['messages'] as $m) {
                            ChaparStorage::purgeAttachment($m['attachment'] ?? null);
                        }
                        ChaparStorage::mutateShard(
                            'topic_' . $tid,
                            [ChaparStorage::class, 'defaultTopic'],
                            function (array &$tState) {
                                $tState = ChaparStorage::defaultTopic();
                            }
                        );
                        $meta['topics'][$tid]['version'] = (int)($meta['topics'][$tid]['version'] ?? 1) + 1;
                        $meta['topics'][$tid]['max_msg_id'] = 0;
                    }
                    return ['success' => true, 'message' => 'تمام پیام‌ها و پیوست‌های تمام تاپیک‌ها منهدم شدند.'];
                }

                $dirty = false;
                return ['success' => false, 'message' => 'فرمان مدیریتی نامعتبر.'];
            }
        )['result'];

        chaparJsonOut($adminTx);
    }

    chaparJsonOut(['success' => false, 'message' => 'اکشن نامعتبر است.'], 400);
}
header('Content-Type: text/html; charset=utf-8');

$sessionData = ChaparSession::bootReadOnly();
$metaState = ChaparStorage::readShard('meta', [ChaparStorage::class, 'defaultMeta']);
$appName = htmlspecialchars((string)($metaState['config']['app_name'] ?? 'چاپار'), ENT_QUOTES, 'UTF-8');
$adminUserLower = mb_strtolower((string)($metaState['config']['admin_username'] ?? 'admin'), 'UTF-8');

$authenticatedUser = null;
if (!empty($sessionData['user_id'])) {
    $uid = (int)$sessionData['user_id'];
    $candidate = $metaState['users'][$uid] ?? null;
    $ipNow = chaparClientIp();
    $isBanned = !$candidate
        || (!empty($candidate['banned']) && ($candidate['role'] ?? '') !== 'admin')
        || in_array($ipNow, $metaState['banned_ips'] ?? [], true);

    if ($isBanned) {
        ChaparSession::destroy();
    } else {
        $authenticatedUser = $candidate;
    }
}

if ($authenticatedUser === null) {
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $appName; ?> — درگاه ورود</title>
    <style>
        :root {
            --primary: #6d5dfc;
            --primary-hover: #5b4df0;
            --bg-color: #090b10;
            --surface: rgba(18, 21, 31, 0.92);
            --text: #f3f4f6;
            --text-muted: #9ca3af;
            --border: rgba(255, 255, 255, 0.08);
            --error: #f87171;
            --emerald: #10b981;
        }
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Tahoma, sans-serif;
            background: radial-gradient(circle at 50% 0%, #171a2b, var(--bg-color) 70%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            color: var(--text);
        }
        .login-shell {
            background: var(--surface);
            padding: 2.2rem 1.8rem;
            border-radius: 22px;
            box-shadow: 0 24px 48px rgba(0, 0, 0, 0.6), inset 0 0 0 1px var(--border);
            max-width: 410px;
            width: 100%;
            text-align: center;
        }
        .security-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 5px 12px;
            border-radius: 999px;
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #6ee7b7;
            font-size: 0.76rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }
        .login-shell h1 {
            font-size: 1.9rem;
            font-weight: 800;
            margin-bottom: 0.35rem;
            background: linear-gradient(135deg, #ffffff, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle {
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-bottom: 1.6rem;
        }
        .field-group {
            text-align: right;
            margin-bottom: 1rem;
        }
        .field-label {
            display: block;
            font-size: 0.78rem;
            color: var(--text-muted);
            margin-bottom: 5px;
            padding-right: 4px;
        }
        .field-input {
            width: 100%;
            padding: 13px 15px;
            background: rgba(0, 0, 0, 0.32);
            border: 1px solid var(--border);
            border-radius: 13px;
            font-size: 0.95rem;
            color: var(--text);
            outline: none;
            font-family: inherit;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .field-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(109, 93, 252, 0.2);
        }
        #adminPassGroup { display: none; }
        .crypto-box {
            background: rgba(16, 185, 129, 0.05);
            border: 1px dashed rgba(16, 185, 129, 0.28);
            border-radius: 14px;
            padding: 10px 12px;
            margin-bottom: 1.2rem;
            text-align: right;
        }
        .crypto-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.76rem;
            color: #6ee7b7;
            margin-bottom: 6px;
        }
        .crypto-gen-btn {
            background: rgba(16, 185, 129, 0.18);
            color: #a7f3d0;
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 3px 9px;
            border-radius: 8px;
            font-size: 0.72rem;
            cursor: pointer;
            font-family: inherit;
        }
        .crypto-gen-btn:hover { background: rgba(16, 185, 129, 0.28); }
        .submit-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            color: #fff;
            border: none;
            border-radius: 13px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            font-family: inherit;
            transition: transform 0.15s, opacity 0.15s;
            box-shadow: 0 8px 20px rgba(109, 93, 252, 0.3);
        }
        .submit-btn:hover { transform: translateY(-1px); }
        .submit-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .error-msg {
            color: var(--error);
            margin-top: 0.9rem;
            font-size: 0.86rem;
            min-height: 20px;
        }
    </style>
</head>
<body>
    <div class="login-shell">
        <div class="security-pill">🔒 رله کور • رمزنگاری AES-256-GCM در مرورگر</div>
        <h1><?php echo $appName; ?></h1>
        <p class="subtitle">شبکه پیام‌رسان مستقل و بدون پایگاه‌داده</p>

        <div class="field-group">
            <label class="field-label" for="loginUsername">نام کاربری</label>
            <input type="text" id="loginUsername" class="field-input" placeholder="نام نمایشی خود را وارد کنید..." maxlength="32" autocomplete="off">
        </div>

        <div class="field-group" id="adminPassGroup">
            <label class="field-label" for="loginPassword">رمز عبور مدیریت</label>
            <input type="password" id="loginPassword" class="field-input" placeholder="رمز عبور مدیر سیستم...">
        </div>

        <div class="crypto-box">
            <div class="crypto-head">
                <span>🔑 کلید رمزنگاری سرتاسری (محلی در #Hash)</span>
                <button type="button" class="crypto-gen-btn" id="genKeyBtn">تولید کلید تصادفی</button>
            </div>
            <input type="text" id="roomSecretInput" class="field-input" placeholder="خالی = عمومی / یا کلید مشترک وارد کنید..." autocomplete="off" style="padding: 9px 12px; font-size: 0.84rem;">
        </div>

        <button type="button" class="submit-btn" id="loginSubmitBtn">ورود به <?php echo $appName; ?></button>
        <div id="loginError" class="error-msg"></div>
    </div>

    <script>
        (() => {
            const ADMIN_LOWER = <?php echo json_encode($adminUserLower); ?>;
            const userInp = document.getElementById('loginUsername');
            const passGrp = document.getElementById('adminPassGroup');
            const passInp = document.getElementById('loginPassword');
            const keyInp = document.getElementById('roomSecretInput');
            const genBtn = document.getElementById('genKeyBtn');
            const subBtn = document.getElementById('loginSubmitBtn');
            const errBox = document.getElementById('loginError');

            const initialHash = decodeURIComponent(window.location.hash.slice(1));
            if (initialHash) {
                keyInp.value = initialHash;
            }

            const cachedName = localStorage.getItem('chapar_username');
            if (cachedName) {
                userInp.value = cachedName;
            }

            function syncAdminField() {
                const isAdm = userInp.value.trim().toLowerCase() === ADMIN_LOWER;
                passGrp.style.display = isAdm ? 'block' : 'none';
            }
            userInp.addEventListener('input', syncAdminField);
            syncAdminField();

            genBtn.addEventListener('click', () => {
                const bytes = new Uint8Array(12);
                window.crypto.getRandomValues(bytes);
                const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
                keyInp.value = hex;
                window.location.hash = encodeURIComponent(hex);
            });

            async function performLogin() {
                const username = userInp.value.trim();
                const password = passInp.value;
                const secret = keyInp.value.trim();

                if (username.length < 2) {
                    errBox.textContent = 'نام کاربری باید حداقل ۲ کاراکتر باشد.';
                    return;
                }

                if (secret) {
                    window.location.hash = encodeURIComponent(secret);
                } else {
                    history.replaceState(null, '', window.location.pathname + window.location.search);
                }

                subBtn.disabled = true;
                subBtn.textContent = 'در حال برقراری نشست...';
                errBox.textContent = '';

                try {
                    const body = new URLSearchParams({ action: 'login', username, password });
                    const res = await fetch('', { method: 'POST', body });
                    const data = await res.json();

                    if (data.success) {
                        localStorage.setItem('chapar_username', data.username);
                        window.location.reload();
                    } else {
                        errBox.textContent = data.message || 'خطا در ورود.';
                        subBtn.disabled = false;
                        subBtn.textContent = 'ورود به <?php echo $appName; ?>';
                        if (data.require_password) {
                            passGrp.style.display = 'block';
                            passInp.focus();
                        }
                    }
                } catch {
                    errBox.textContent = 'خطا در ارتباط با سرور.';
                    subBtn.disabled = false;
                    subBtn.textContent = 'ورود به <?php echo $appName; ?>';
                }
            }

            subBtn.addEventListener('click', performLogin);
            document.addEventListener('keydown', e => {
                if (e.key === 'Enter') performLogin();
            });
        })();
    </script>
</body>
</html>
<?php
    exit;
}

$currentUserId = (int)$authenticatedUser['user_id'];
$currentUsername = (string)$authenticatedUser['username'];
$isAdmin = (($authenticatedUser['role'] ?? '') === 'admin');
$csrfToken = (string)$sessionData['csrf_token'];
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $appName; ?> — <?php echo htmlspecialchars($currentUsername, ENT_QUOTES, 'UTF-8'); ?></title>
    <style>
        :root {
            --bg-body: #0b0d14;
            --bg-panel: rgba(20, 23, 35, 0.92);
            --bg-elevated: #1b2030;
            --bg-msg-other: #1f2437;
            --bg-msg-me: linear-gradient(135deg, #6d5dfc, #8b5cf6);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --border-glass: rgba(255, 255, 255, 0.08);
            --accent: #6d5dfc;
            --accent-hover: #5b4df0;
            --danger: #ef4444;
            --success: #10b981;
            --gold: #eab308;
            --shadow-sm: 0 3px 12px rgba(0, 0, 0, 0.22);
            --shadow-lg: 0 12px 32px rgba(0, 0, 0, 0.45);
        }
        .light-mode {
            --bg-body: #f1f5f9;
            --bg-panel: rgba(255, 255, 255, 0.95);
            --bg-elevated: #e2e8f0;
            --bg-msg-other: #ffffff;
            --bg-msg-me: linear-gradient(135deg, #6d5dfc, #7c3aed);
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border-glass: rgba(0, 0, 0, 0.09);
            --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 10px 25px rgba(0, 0, 0, 0.12);
        }
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Tahoma, sans-serif;
            background: var(--bg-body);
            color: var(--text-main);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            transition: background 0.2s, color 0.2s;
        }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(109, 93, 252, 0.4); border-radius: 8px; }

        .top-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.6rem 1.1rem;
            background: var(--bg-panel);
            border-bottom: 1px solid var(--border-glass);
            z-index: 100;
            flex-shrink: 0;
        }
        .brand-section {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 800;
            font-size: 1.1rem;
        }
        .crypto-status-btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid var(--border-glass);
            font-family: inherit;
        }
        .crypto-status-btn.secured {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border-color: rgba(16, 185, 129, 0.35);
        }
        .crypto-status-btn.plain {
            background: rgba(239, 68, 68, 0.12);
            color: #f87171;
            border-color: rgba(239, 68, 68, 0.3);
        }
        .header-tools {
            display: flex;
            align-items: center;
            gap: 7px;
            flex-wrap: wrap;
        }
        .tool-btn {
            background: var(--bg-elevated);
            color: var(--text-main);
            border: 1px solid var(--border-glass);
            border-radius: 10px;
            padding: 6px 10px;
            font-size: 0.82rem;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            font-family: inherit;
            transition: border-color 0.15s;
        }
        .tool-btn:hover { border-color: var(--accent); }
        .online-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            display: inline-block;
        }
        .online-strip {
            display: none;
            gap: 8px;
            padding: 0.5rem 1.1rem;
            background: var(--bg-elevated);
            border-bottom: 1px solid var(--border-glass);
            overflow-x: auto;
            white-space: nowrap;
            font-size: 0.8rem;
        }
        .online-strip.visible { display: flex; }
        .online-chip {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 3px 10px;
            border-radius: 999px;
            background: var(--bg-panel);
            border: 1px solid var(--border-glass);
        }

        .chat-layout {
            flex: 1;
            display: flex;
            flex-direction: column;
            max-width: 1180px;
            width: 100%;
            margin: 0 auto;
            padding: 0.75rem 1rem;
            min-height: 0;
            position: relative;
        }

        .topics-bar {
            display: flex;
            align-items: center;
            gap: 8px;
            overflow-x: auto;
            padding-bottom: 0.55rem;
            margin-bottom: 0.5rem;
            scrollbar-width: none;
            flex-shrink: 0;
        }
        .topics-bar::-webkit-scrollbar { display: none; }
        .topic-pill {
            background: var(--bg-panel);
            border: 1px solid var(--border-glass);
            color: var(--text-main);
            padding: 6px 14px;
            border-radius: 12px;
            font-size: 0.86rem;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            white-space: nowrap;
            transition: border-color 0.15s, background 0.15s;
        }
        .topic-pill:hover { border-color: var(--accent); }
        .topic-pill.active {
            background: var(--accent);
            color: #fff;
            border-color: var(--accent);
            font-weight: 600;
        }
        .unread-counter {
            background: var(--danger);
            color: #fff;
            border-radius: 999px;
            padding: 1px 6px;
            font-size: 0.72rem;
            font-weight: 700;
        }
        .topic-admin-act {
            background: rgba(0, 0, 0, 0.25);
            border: none;
            color: inherit;
            border-radius: 6px;
            padding: 2px 5px;
            font-size: 0.72rem;
            cursor: pointer;
        }
        .topic-admin-act:hover { background: var(--danger); color: #fff; }
        .topic-QuickAdd {
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        .topic-QuickAdd input {
            background: var(--bg-panel);
            border: 1px solid var(--border-glass);
            color: var(--text-main);
            border-radius: 10px;
            padding: 5px 10px;
            font-size: 0.82rem;
            width: 130px;
            outline: none;
            font-family: inherit;
        }
        .topic-QuickAdd button {
            background: var(--success);
            color: #fff;
            border: none;
            border-radius: 10px;
            padding: 5px 10px;
            cursor: pointer;
            font-weight: 700;
        }

        .pinned-bar {
            background: rgba(234, 179, 8, 0.09);
            border: 1px solid rgba(234, 179, 8, 0.28);
            border-radius: 14px;
            padding: 8px 14px;
            margin-bottom: 0.55rem;
            flex-shrink: 0;
            display: none;
        }
        .pinned-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            color: var(--gold);
            font-size: 0.84rem;
            font-weight: 700;
        }
        .pinned-items {
            max-height: 110px;
            overflow-y: auto;
            margin-top: 6px;
        }
        .pinned-items.collapsed { display: none; }
        .pinned-row {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.8rem;
            padding: 4px 0;
            border-bottom: 1px dashed rgba(234, 179, 8, 0.2);
            cursor: pointer;
            color: var(--text-main);
        }
        .pinned-row:last-child { border-bottom: none; }
        .pinned-row:hover { opacity: 0.85; }
        .pinned-user { color: var(--gold); font-weight: 700; flex-shrink: 0; }
        .pinned-snippet {
            color: var(--text-muted);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .messages-viewport {
            flex: 1;
            overflow-y: auto;
            padding: 1.1rem;
            background: var(--bg-panel);
            border-radius: 20px;
            border: 1px solid var(--border-glass);
            box-shadow: var(--shadow-lg);
            display: flex;
            flex-direction: column;
            gap: 0.9rem;
            min-height: 0;
        }
        .empty-state {
            margin: auto;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.92rem;
            padding: 2rem;
        }

        .msg-row {
            display: flex;
            flex-direction: column;
            max-width: 76%;
            align-self: flex-start;
            position: relative;
        }
        .msg-row.own { align-self: flex-end; }
        .msg-meta {
            display: flex;
            align-items: center;
            gap: 7px;
            margin-bottom: 4px;
            padding: 0 4px;
            font-size: 0.78rem;
        }
        .msg-author { font-weight: 700; color: var(--accent); }
        .msg-row.own .msg-author { color: var(--text-muted); }
        .admin-tag {
            background: rgba(234, 179, 8, 0.18);
            color: var(--gold);
            border: 1px solid rgba(234, 179, 8, 0.35);
            border-radius: 6px;
            padding: 0 5px;
            font-size: 0.68rem;
            font-weight: 700;
        }
        .msg-time { color: var(--text-muted); font-size: 0.72rem; }
        .e2e-lock-icon { font-size: 0.72rem; color: var(--success); }

        .reply-box {
            background: rgba(0, 0, 0, 0.18);
            border-right: 3px solid var(--accent);
            border-radius: 8px;
            padding: 5px 10px;
            margin-bottom: 6px;
            font-size: 0.78rem;
            cursor: pointer;
            color: var(--text-muted);
        }
        .msg-row.own .reply-box {
            background: rgba(255, 255, 255, 0.14);
            border-right-color: #fff;
            color: rgba(255, 255, 255, 0.9);
        }
        .reply-box-user { font-weight: 700; display: block; margin-bottom: 2px; }

        .msg-bubble {
            background: var(--bg-msg-other);
            color: var(--text-main);
            padding: 10px 14px;
            border-radius: 18px 18px 18px 4px;
            font-size: 0.95rem;
            line-height: 1.55;
            border: 1px solid var(--border-glass);
            box-shadow: var(--shadow-sm);
            word-break: break-word;
        }
        .msg-row.own .msg-bubble {
            background: var(--bg-msg-me);
            color: #fff;
            border-radius: 18px 18px 4px 18px;
            border: none;
        }
        .msg-text { white-space: pre-wrap; }
        .msg-text.collapsed {
            max-height: 140px;
            overflow: hidden;
            position: relative;
        }
        .expand-btn {
            background: none;
            border: none;
            color: var(--accent);
            font-size: 0.78rem;
            font-weight: 700;
            cursor: pointer;
            margin-top: 4px;
            font-family: inherit;
        }
        .msg-row.own .expand-btn { color: #fde047; }

        .msg-media { margin-bottom: 6px; }
        .msg-img {
            max-width: 260px;
            max-height: 220px;
            border-radius: 12px;
            cursor: pointer;
            display: block;
        }
        .npvt-dl {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 7px 12px;
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid var(--border-glass);
            border-radius: 10px;
            color: inherit;
            text-decoration: none;
            font-size: 0.84rem;
            font-weight: 600;
        }

        .msg-footer {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 5px;
            margin-top: 4px;
            opacity: 0.75;
            transition: opacity 0.15s;
        }
        .msg-row:hover .msg-footer { opacity: 1; }
        .msg-act-btn {
            background: var(--bg-elevated);
            border: 1px solid var(--border-glass);
            color: var(--text-muted);
            border-radius: 8px;
            padding: 2px 8px;
            font-size: 0.73rem;
            cursor: pointer;
            font-family: inherit;
        }
        .msg-act-btn:hover { color: var(--text-main); border-color: var(--accent); }
        .msg-act-btn.pinned { color: var(--gold); border-color: rgba(234, 179, 8, 0.4); }
        .meta-pill {
            font-size: 0.71rem;
            color: var(--text-muted);
            padding: 1px 6px;
        }

        .typing-bar {
            min-height: 22px;
            padding: 2px 10px;
            font-size: 0.78rem;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            gap: 6px;
            flex-shrink: 0;
        }

        .composer-reply-bar {
            display: none;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-elevated);
            border: 1px solid var(--border-glass);
            border-right: 3px solid var(--accent);
            border-radius: 12px;
            padding: 6px 12px;
            margin-bottom: 6px;
            font-size: 0.82rem;
            flex-shrink: 0;
        }
        .composer-reply-bar.active { display: flex; }
        .composer-cancel-btn {
            background: none;
            border: none;
            color: var(--danger);
            font-size: 1rem;
            cursor: pointer;
            padding: 0 4px;
        }

        .composer-box {
            background: var(--bg-panel);
            border: 1px solid var(--border-glass);
            border-radius: 18px;
            padding: 8px 10px;
            display: flex;
            align-items: flex-end;
            gap: 8px;
            box-shadow: var(--shadow-lg);
            flex-shrink: 0;
        }
        .composer-input {
            flex: 1;
            background: rgba(0, 0, 0, 0.18);
            border: 1px solid var(--border-glass);
            color: var(--text-main);
            border-radius: 13px;
            padding: 10px 14px;
            font-size: 0.94rem;
            resize: none;
            max-height: 120px;
            outline: none;
            font-family: inherit;
        }
        .composer-input:focus { border-color: var(--accent); }
        .icon-btn {
            width: 42px;
            height: 42px;
            border-radius: 13px;
            border: 1px solid var(--border-glass);
            background: var(--bg-elevated);
            color: var(--text-main);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            font-size: 1.1rem;
            flex-shrink: 0;
            transition: transform 0.15s, background 0.15s;
        }
        .icon-btn:hover { border-color: var(--accent); }
        .icon-btn.primary {
            background: var(--accent);
            color: #fff;
            border-color: var(--accent);
        }
        .icon-btn.primary:hover { background: var(--accent-hover); }

        .float-unread-btn {
            position: absolute;
            bottom: 85px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--danger);
            color: #fff;
            border: none;
            border-radius: 999px;
            padding: 8px 18px;
            font-size: 0.84rem;
            font-weight: 700;
            cursor: pointer;
            box-shadow: var(--shadow-lg);
            display: none;
            z-index: 50;
            font-family: inherit;
        }

        .side-drawer {
            position: fixed;
            top: 0;
            bottom: 0;
            width: 330px;
            max-width: 88vw;
            background: var(--bg-panel);
            backdrop-filter: blur(16px);
            border-left: 1px solid var(--border-glass);
            box-shadow: var(--shadow-lg);
            z-index: 1500;
            padding: 1.2rem;
            display: flex;
            flex-direction: column;
            transition: transform 0.25s ease;
        }
        .side-drawer.right { right: 0; transform: translateX(105%); }
        .side-drawer.right.open { transform: translateX(0); }
        .drawer-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 800;
            font-size: 1.05rem;
            padding-bottom: 0.8rem;
            border-bottom: 1px solid var(--border-glass);
            margin-bottom: 0.9rem;
        }
        .drawer-close {
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 1.5rem;
            cursor: pointer;
        }
        .drawer-body { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 0.7rem; }

        .news-card {
            background: var(--bg-elevated);
            border: 1px solid var(--border-glass);
            border-radius: 14px;
            padding: 0.75rem 0.9rem;
            font-size: 0.88rem;
        }
        .news-text { white-space: pre-wrap; word-break: break-word; line-height: 1.5; }
        .news-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 8px;
            padding-top: 6px;
            border-top: 1px solid var(--border-glass);
            font-size: 0.75rem;
            color: var(--text-muted);
        }
        .react-group { display: flex; gap: 5px; }
        .react-pill {
            background: var(--bg-panel);
            border: 1px solid var(--border-glass);
            color: var(--text-main);
            border-radius: 999px;
            padding: 2px 8px;
            font-size: 0.76rem;
            cursor: pointer;
        }
        .react-pill.active { background: var(--accent); color: #fff; border-color: var(--accent); }

        .modal-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.72);
            backdrop-filter: blur(5px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
            padding: 1rem;
        }
        .modal-backdrop.open { display: flex; }
        .modal-card {
            background: var(--bg-panel);
            border: 1px solid var(--border-glass);
            border-radius: 20px;
            width: 100%;
            max-width: 680px;
            max-height: 88vh;
            display: flex;
            flex-direction: column;
            box-shadow: var(--shadow-lg);
            overflow: hidden;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.3rem;
            border-bottom: 1px solid var(--border-glass);
            font-weight: 800;
        }
        .modal-body {
            padding: 1.2rem 1.3rem;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 1.1rem;
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 8px;
        }
        .stat-box {
            background: var(--bg-elevated);
            border: 1px solid var(--border-glass);
            border-radius: 12px;
            padding: 10px;
            text-align: center;
        }
        .stat-val { font-size: 1.2rem; font-weight: 800; color: var(--accent); }
        .stat-lbl { font-size: 0.74rem; color: var(--text-muted); margin-top: 2px; }
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }
        .form-control {
            display: flex;
            flex-direction: column;
            gap: 4px;
            font-size: 0.8rem;
        }
        .form-control input[type="text"],
        .form-control input[type="number"],
        .form-control input[type="password"] {
            background: var(--bg-elevated);
            border: 1px solid var(--border-glass);
            color: var(--text-main);
            border-radius: 9px;
            padding: 8px 10px;
            font-family: inherit;
            outline: none;
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8rem;
        }
        .data-table th, .data-table td {
            padding: 7px 8px;
            text-align: right;
            border-bottom: 1px solid var(--border-glass);
        }
        .btn-sm {
            padding: 5px 11px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-size: 0.78rem;
            font-weight: 600;
            font-family: inherit;
        }
        .btn-accent { background: var(--accent); color: #fff; }
        .btn-danger { background: var(--danger); color: #fff; }
        .btn-success { background: var(--success); color: #fff; }

         body {
            height: 100vh;
            height: 100dvh;
        }
        .topics-bar, .messages-viewport, .online-strip {
            -webkit-overflow-scrolling: touch;
        }
        @media (max-width: 768px) {
            .top-header {
                padding: 0.45rem 0.6rem;
                flex-wrap: wrap;
                gap: 6px;
            }
            .brand-section {
                font-size: 0.95rem;
                gap: 6px;
            }
            .crypto-status-btn {
                padding: 3px 8px;
                font-size: 0.7rem;
            }
            .header-tools {
                gap: 4px;
                margin-right: auto;
            }
            .tool-btn {
                padding: 5px 8px;
                font-size: 0.75rem;
                border-radius: 8px;
            }
            .chat-layout {
                padding: 0.35rem 0.45rem;
            }
            .topics-bar {
                gap: 6px;
                padding-bottom: 0.4rem;
                margin-bottom: 0.35rem;
            }
            .topic-pill {
                padding: 5px 10px;
                font-size: 0.8rem;
                border-radius: 10px;
            }
            .topic-QuickAdd input {
                width: 115px;
                font-size: 16px;
                padding: 4px 8px;
            }
            .topic-QuickAdd button {
                padding: 5px 10px;
                font-size: 0.9rem;
            }
            .messages-viewport {
                padding: 0.65rem;
                border-radius: 14px;
                gap: 0.7rem;
            }
            .msg-row {
                max-width: 92%;
            }
            .msg-bubble {
                padding: 8px 11px;
                font-size: 0.9rem;
            }
            .msg-img {
                max-width: 100%;
                max-height: 200px;
                height: auto;
            }
            .msg-footer {
                opacity: 1;
                flex-wrap: wrap;
                gap: 4px;
            }
            .msg-act-btn {
                padding: 3px 7px;
                font-size: 0.7rem;
            }
            .composer-box {
                padding: 6px 8px;
                border-radius: 14px;
                gap: 6px;
            }
            .composer-input {
                font-size: 16px;
                padding: 8px 11px;
                border-radius: 10px;
            }
            .icon-btn {
                width: 38px;
                height: 38px;
                border-radius: 10px;
                font-size: 1rem;
            }
            .float-unread-btn {
                bottom: 70px;
                padding: 6px 14px;
                font-size: 0.78rem;
            }
            .side-drawer {
                width: 100%;
                max-width: 100vw;
                padding: 1rem;
            }
            .modal-backdrop {
                padding: 0.4rem;
            }
            .modal-card {
                max-height: 92dvh;
                border-radius: 14px;
            }
            .modal-header {
                padding: 0.75rem 1rem;
                font-size: 0.92rem;
            }
            .modal-body {
                padding: 0.85rem 1rem;
                gap: 0.85rem;
            }
            .stat-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .form-grid {
                grid-template-columns: 1fr;
            }
            .form-control input[type="text"],
            .form-control input[type="number"],
            .form-control input[type="password"],
            #newsInput,
            #e2eKeyModalInput {
                font-size: 16px;
            }
            .data-table {
                display: block;
                overflow-x: auto;
                white-space: nowrap;
                -webkit-overflow-scrolling: touch;
            }
        }
    </style>
</head>
<body>
    <header class="top-header">
        <div class="brand-section">
            <span>⚡ <?php echo $appName; ?></span>
            <button type="button" class="crypto-status-btn plain" id="e2eStatusBtn" title="تنظیم کلید رمزنگاری سرتاسری">
                🔓 <span id="e2eStatusText">بدون رمزنگاری</span>
            </button>
        </div>
        <div class="header-tools">
            <button type="button" class="tool-btn" id="onlineToggleBtn" title="مشاهده کاربران آنلاین">
                <span class="online-dot"></span>
                <span id="onlineCountBadge">1</span> آنلاین
            </button>
            <button type="button" class="tool-btn" id="newsOpenBtn">📰 اخبار</button>
            <?php if ($isAdmin): ?>
                <button type="button" class="tool-btn" id="adminOpenBtn">⚙️ پنل مدیریت</button>
            <?php endif; ?>
            <button type="button" class="tool-btn" id="themeSwitchBtn" title="تغییر تم">🌓</button>
            <button type="button" class="tool-btn" id="logoutBtn" title="خروج از حساب" style="color:var(--danger);">🚪</button>
        </div>
    </header>

    <div class="online-strip" id="onlineStrip"></div>

    <main class="chat-layout">
        <div class="topics-bar" id="topicsBar"></div>

        <div class="pinned-bar" id="pinnedBar">
            <div class="pinned-head" id="pinnedToggleHead">
                <span>📌 پیام‌های سنجاق‌شده</span>
                <span id="pinnedCaret">▼</span>
            </div>
            <div class="pinned-items" id="pinnedList"></div>
        </div>

        <div class="messages-viewport" id="messagesViewport">
            <div class="empty-state">در حال همگام‌سازی...</div>
        </div>

        <button type="button" class="float-unread-btn" id="unreadFloatBtn">⬇️ پیام جدید</button>

        <div class="typing-bar" id="typingBar"></div>

        <div class="composer-reply-bar" id="composerStateBar">
            <span id="composerStateText"></span>
            <button type="button" class="composer-cancel-btn" id="composerCancelBtn">&times;</button>
        </div>

        <div class="composer-box">
            <label for="imgUploadInput" class="icon-btn" id="imgUploadLabel" title="ارسال تصویر">📎</label>
            <input type="file" id="imgUploadInput" accept="image/jpeg,image/png,image/gif,image/webp" style="display:none;">

            <?php if ($isAdmin): ?>
                <label for="npvtUploadInput" class="icon-btn" title="ارسال فایل npvt">📁</label>
                <input type="file" id="npvtUploadInput" accept=".npvt" style="display:none;">
            <?php endif; ?>

            <textarea class="composer-input" id="messageInput" rows="1" placeholder="پیام خود را بنویسید..."></textarea>
            <button type="button" class="icon-btn primary" id="sendBtn" title="ارسال">➤</button>
        </div>
    </main>

    <!-- پنل کشویی اخبار -->
    <aside class="side-drawer right" id="newsDrawer">
        <div class="drawer-head">
            <span>📰 اطلاعیه‌ها و اخبار</span>
            <button type="button" class="drawer-close" id="newsCloseBtn">&times;</button>
        </div>
        <div style="display:flex; gap:6px; margin-bottom:0.8rem;">
            <input type="text" id="newsInput" placeholder="متن خبر جدید..." style="flex:1; padding:8px 10px; border-radius:10px; border:1px solid var(--border-glass); background:var(--bg-elevated); color:var(--text-main); outline:none; font-family:inherit;">
            <button type="button" class="btn-sm btn-accent" id="newsSubmitBtn">ثبت</button>
        </div>
        <div class="drawer-body" id="newsListContainer"></div>
        <?php if ($isAdmin): ?>
            <button type="button" class="btn-sm btn-danger" id="newsPurgeBtn" style="margin-top:0.8rem; padding:8px;">پاک‌سازی همه اخبار</button>
        <?php endif; ?>
    </aside>

    <!-- مودال تنظیم کلید رمزنگاری E2EE -->
    <div class="modal-backdrop" id="e2eModal">
        <div class="modal-card" style="max-width:440px;">
            <div class="modal-header">
                <span>🔒 رمزنگاری سرتاسری (AES-256-GCM)</span>
                <button type="button" class="drawer-close" id="e2eModalClose">&times;</button>
            </div>
            <div class="modal-body">
                <p style="font-size:0.82rem; color:var(--text-muted); line-height:1.6;">
                    کلید رمزنگاری فقط در مرورگر شما و در بخش <code>#Hash</code> آدرس قرار می‌گیرد و هرگز به سرور ارسال نمی‌شود. تمام افراد حاضر در گفتگو باید کلید یکسانی داشته باشند.
                </p>
                <div class="form-control">
                    <label>کلید فعلی اتاق:</label>
                    <input type="text" id="e2eKeyModalInput" placeholder="خالی = ارسال به صورت متن عادی..." autocomplete="off">
                </div>
                <div style="display:flex; gap:8px; justify-content:flex-end;">
                    <button type="button" class="btn-sm btn-success" id="e2eRandomBtn">تولید کلید تصادفی</button>
                    <button type="button" class="btn-sm btn-accent" id="e2eCopyLinkBtn">کپی لینک دعوت امن</button>
                    <button type="button" class="btn-sm btn-accent" id="e2eApplyBtn">اعمال کلید</button>
                </div>
            </div>
        </div>
    </div>

    <?php if ($isAdmin): ?>
    <!-- مودال پنل مدیریت جامع -->
    <div class="modal-backdrop" id="adminModal">
        <div class="modal-card">
            <div class="modal-header">
                <span>⚙️ پنل مدیریت چاپار</span>
                <button type="button" class="drawer-close" id="adminModalClose">&times;</button>
            </div>
            <div class="modal-body">
                <div class="stat-grid" id="adminStatsGrid"></div>

                <form id="adminConfigForm" class="form-grid" onsubmit="return false;">
                    <div class="form-control">
                        <label>نام سامانه</label>
                        <input type="text" id="cfgAppName" required>
                    </div>
                    <div class="form-control">
                        <label>نام کاربری مدیر</label>
                        <input type="text" id="cfgAdminUser" required>
                    </div>
                    <div class="form-control">
                        <label>رمز عبور جدید مدیر (اختیاری)</label>
                        <input type="password" id="cfgAdminPass" placeholder="بدون تغییر = خالی بگذارید">
                    </div>
                    <div class="form-control">
                        <label>حذف خودکار پیام‌ها پس از (ساعت - ۰=غیرفعال)</label>
                        <input type="number" id="cfgTtlHours" min="0" max="8760">
                    </div>
                    <div class="form-control">
                        <label>حداکثر پیام ذخیره در هر تاپیک</label>
                        <input type="number" id="cfgMaxMsgs" min="50" max="10000">
                    </div>
                    <div class="form-control" style="justify-content:center; gap:8px;">
                        <label style="display:flex; align-items:center; gap:6px; cursor:pointer;">
                            <input type="checkbox" id="cfgChatLocked"> قفل کردن ارسال پیام برای کاربران
                        </label>
                        <label style="display:flex; align-items:center; gap:6px; cursor:pointer;">
                            <input type="checkbox" id="cfgAllowUploads"> اجازه آپلود تصویر به کاربران
                        </label>
                    </div>
                </form>

                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                    <button type="button" class="btn-sm btn-accent" id="adminSaveConfigBtn">💾 ذخیره تنظیمات</button>
                    <button type="button" class="btn-sm btn-danger" id="adminPurgeAllBtn">☢️ امحای کامل تمام پیام‌ها و فایل‌ها</button>
                </div>

                <h4 style="font-size:0.88rem; border-top:1px solid var(--border-glass); padding-top:0.8rem;">👥 کاربران و مدیریت دسترسی (IP)</h4>
                <div style="max-height:220px; overflow-y:auto;">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>کاربر</th>
                                <th>آدرس IP</th>
                                <th>وضعیت</th>
                                <th>عملیات</th>
                            </tr>
                        </thead>
                        <tbody id="adminUsersTbody"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- مودال نمایش بزرگ تصویر -->
    <div class="modal-backdrop" id="imagePreviewModal">
        <img id="imagePreviewTarget" src="" alt="Preview" style="max-width:92vw; max-height:88vh; border-radius:12px;">
    </div>
    <script>
    (() => {
        'use strict';

        const CONFIG = {
            userId: <?php echo (int)$currentUserId; ?>,
            username: <?php echo json_encode($currentUsername); ?>,
            isAdmin: <?php echo $isAdmin ? 'true' : 'false'; ?>,
            csrfToken: <?php echo json_encode($csrfToken); ?>,
            pollIntervalMs: 2000,
            hiddenPollIntervalMs: 6000
        };

        /* =========================================================================
         * 1. E2EE Cryptography Engine (Memoized PBKDF2 + AES-256-GCM)
         * ========================================================================= */
        const CryptoEngine = (() => {
            const ENC_PREFIX = 'E2E1:';
            const SALT = new TextEncoder().encode('Chapar-ZeroKnowledge-Salt-v1');
            let cachedPassphrase = '';
            let cachedCryptoKey = null;

            function toBase64(bytes) {
                let binary = '';
                for (let i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                return btoa(binary);
            }

            function fromBase64(b64) {
                const binary = atob(b64);
                const out = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                    out[i] = binary.charCodeAt(i);
                }
                return out;
            }

            async function setPassphrase(secret) {
                const clean = (secret || '').trim();
                if (clean === cachedPassphrase && (clean === '' || cachedCryptoKey !== null)) {
                    return;
                }
                cachedPassphrase = clean;
                if (!clean || !window.crypto || !window.crypto.subtle) {
                    cachedCryptoKey = null;
                    return;
                }
                const baseKey = await window.crypto.subtle.importKey(
                    'raw',
                    new TextEncoder().encode(clean),
                    { name: 'PBKDF2' },
                    false,
                    ['deriveKey']
                );
                cachedCryptoKey = await window.crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt: SALT, iterations: 100000, hash: 'SHA-256' },
                    baseKey,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt', 'decrypt']
                );
            }

            function isActive() {
                return cachedCryptoKey !== null;
            }

            function getPassphrase() {
                return cachedPassphrase;
            }

            async function encryptText(plain) {
                if (!cachedCryptoKey || !plain) {
                    return { payload: plain, encrypted: false };
                }
                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                const encoded = new TextEncoder().encode(plain);
                const cipherBuf = await window.crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv },
                    cachedCryptoKey,
                    encoded
                );
                const payload = ENC_PREFIX + toBase64(iv) + ':' + toBase64(new Uint8Array(cipherBuf));
                return { payload, encrypted: true };
            }

            async function decryptText(payload) {
                if (typeof payload !== 'string' || !payload.startsWith(ENC_PREFIX)) {
                    return { text: payload || '', status: 'plain' };
                }
                if (!cachedCryptoKey) {
                    return { text: '🔒 [پیام رمزنگاری‌شده — کلید اتاق را در #Hash وارد کنید]', status: 'locked' };
                }
                try {
                    const parts = payload.slice(ENC_PREFIX.length).split(':');
                    if (parts.length !== 2) {
                        return { text: '⚠️ [ساختار بسته رمزنگاری نامعتبر]', status: 'error' };
                    }
                    const iv = fromBase64(parts[0]);
                    const cipherBytes = fromBase64(parts[1]);
                    const plainBuf = await window.crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv },
                        cachedCryptoKey,
                        cipherBytes
                    );
                    return { text: new TextDecoder().decode(plainBuf), status: 'decrypted' };
                } catch {
                    return { text: '🔒 [کلید رمزگشایی با این پیام مطابقت ندارد]', status: 'mismatch' };
                }
            }

            return { setPassphrase, isActive, getPassphrase, encryptText, decryptText };
        })();

        /* =========================================================================
         * 2. State Store & Network Client
         * ========================================================================= */
        const State = {
            currentTopicId: 1,
            topicVersion: 0,
            lastMessageId: 0,
            messagesMap: new Map(),
            topics: [],
            unreadCounts: {},
            replyTarget: null,
            editTarget: null,
            typingFlag: -1,
            typingDecayTimer: null,
            syncInFlight: false,
            pollTimer: null,
            unreadInViewport: 0
        };

        async function apiCall(action, params = {}, filePayload = null) {
            const formData = new FormData();
            formData.append('action', action);
            formData.append('csrf_token', CONFIG.csrfToken);

            for (const [k, v] of Object.entries(params)) {
                if (v !== null && v !== undefined) {
                    formData.append(k, String(v));
                }
            }
            if (filePayload) {
                formData.append(filePayload.field, filePayload.file);
            }

            const response = await fetch('', {
                method: 'POST',
                body: formData,
                headers: { 'X-CSRF-Token': CONFIG.csrfToken }
            });
            const data = await response.json();
            if (data && data.logged_out) {
                window.location.reload();
                throw new Error('Session terminated');
            }
            return data;
        }

        function formatRelativeTime(ms) {
            if (!ms) return '';
            const diffSec = Math.floor((Date.now() - ms) / 1000);
            if (diffSec < 45) return 'همین الان';
            if (diffSec < 3600) return Math.floor(diffSec / 60) + ' دقیقه پیش';
            if (diffSec < 86400) return Math.floor(diffSec / 3600) + ' ساعت پیش';
            try {
                const d = new Date(ms);
                return d.toLocaleDateString('fa-IR') + ' ' + d.toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' });
            } catch {
                return '';
            }
        }
        /* =========================================================================
         * 3. Safe DOM Rendering & Event Delegation
         * ========================================================================= */
        const DOM = {
            viewport: document.getElementById('messagesViewport'),
            topicsBar: document.getElementById('topicsBar'),
            pinnedBar: document.getElementById('pinnedBar'),
            pinnedList: document.getElementById('pinnedList'),
            pinnedHead: document.getElementById('pinnedToggleHead'),
            typingBar: document.getElementById('typingBar'),
            onlineBadge: document.getElementById('onlineCountBadge'),
            onlineStrip: document.getElementById('onlineStrip'),
            onlineToggle: document.getElementById('onlineToggleBtn'),
            unreadBtn: document.getElementById('unreadFloatBtn'),
            msgInput: document.getElementById('messageInput'),
            sendBtn: document.getElementById('sendBtn'),
            imgInput: document.getElementById('imgUploadInput'),
            imgLabel: document.getElementById('imgUploadLabel'),
            npvtInput: document.getElementById('npvtUploadInput'),
            stateBar: document.getElementById('composerStateBar'),
            stateText: document.getElementById('composerStateText'),
            stateCancel: document.getElementById('composerCancelBtn'),
            e2eBtn: document.getElementById('e2eStatusBtn'),
            e2eText: document.getElementById('e2eStatusText'),
            e2eModal: document.getElementById('e2eModal'),
            e2eInput: document.getElementById('e2eKeyModalInput'),
            newsDrawer: document.getElementById('newsDrawer'),
            newsList: document.getElementById('newsListContainer'),
            newsInput: document.getElementById('newsInput'),
            imgModal: document.getElementById('imagePreviewModal'),
            imgTarget: document.getElementById('imagePreviewTarget')
        };

        function isNearBottom() {
            return DOM.viewport.scrollHeight - DOM.viewport.scrollTop - DOM.viewport.clientHeight < 90;
        }

        function scrollToBottom() {
            DOM.viewport.scrollTop = DOM.viewport.scrollHeight;
            State.unreadInViewport = 0;
            DOM.unreadBtn.style.display = 'none';
        }

        async function buildMessageNode(msg) {
            const decMain = msg.is_encrypted
                ? await CryptoEngine.decryptText(msg.content)
                : { text: msg.content, status: 'plain' };

            let decReplyText = msg.reply_content || '';
            if (msg.reply_to && msg.reply_encrypted) {
                const rDec = await CryptoEngine.decryptText(msg.reply_content);
                decReplyText = rDec.text;
            }

            msg._plainText = decMain.text;

            const isOwn = Number(msg.user_id) === CONFIG.userId;
            const row = document.createElement('div');
            row.className = 'msg-row' + (isOwn ? ' own' : '');
            row.id = 'msg-' + msg.msg_id;
            row.dataset.msgId = String(msg.msg_id);

            const meta = document.createElement('div');
            meta.className = 'msg-meta';

            const authorSpan = document.createElement('span');
            authorSpan.className = 'msg-author';
            authorSpan.textContent = msg.username;
            meta.appendChild(authorSpan);

            if (msg.is_admin) {
                const badge = document.createElement('span');
                badge.className = 'admin-tag';
                badge.textContent = 'مدیر';
                meta.appendChild(badge);
            }

            if (msg.is_encrypted) {
                const lock = document.createElement('span');
                lock.className = 'e2e-lock-icon';
                lock.textContent = '🔒';
                lock.title = 'رمزنگاری سرتاسری (E2EE)';
                meta.appendChild(lock);
            }

            const timeSpan = document.createElement('span');
            timeSpan.className = 'msg-time';
            timeSpan.textContent = formatRelativeTime(msg.created_at) + (msg.edited_at ? ' (ویرایش‌شده)' : '');
            meta.appendChild(timeSpan);

            row.appendChild(meta);

            if (msg.reply_to && msg.reply_username) {
                const replyBox = document.createElement('div');
                replyBox.className = 'reply-box';
                replyBox.dataset.action = 'jump';
                replyBox.dataset.targetId = String(msg.reply_to);

                const rUser = document.createElement('span');
                rUser.className = 'reply-box-user';
                rUser.textContent = 'پاسخ به ' + msg.reply_username;

                const rText = document.createElement('span');
                const snippet = decReplyText.length > 65 ? decReplyText.slice(0, 62) + '...' : decReplyText;
                rText.textContent = snippet || 'پیام پیوست';

                replyBox.appendChild(rUser);
                replyBox.appendChild(rText);
                row.appendChild(replyBox);
            }

            const bubble = document.createElement('div');
            bubble.className = 'msg-bubble';

            if (msg.is_image && msg.image_path) {
                const mediaWrap = document.createElement('div');
                mediaWrap.className = 'msg-media';
                const img = document.createElement('img');
                img.className = 'msg-img';
                img.src = msg.image_path;
                img.alt = 'تصویر پیوست';
                img.loading = 'lazy';
                img.dataset.action = 'preview-img';
                img.dataset.src = msg.image_path;
                mediaWrap.appendChild(img);
                bubble.appendChild(mediaWrap);
            } else if (msg.is_npvt && msg.npvt_path) {
                const mediaWrap = document.createElement('div');
                mediaWrap.className = 'msg-media';
                const link = document.createElement('a');
                link.className = 'npvt-dl';
                link.href = msg.npvt_path;
                link.download = msg.npvt_filename || 'config.npvt';
                link.textContent = '📥 دانلود فایل کانفیگ: ' + (msg.npvt_filename || 'file.npvt');
                mediaWrap.appendChild(link);
                bubble.appendChild(mediaWrap);
            }

            if (decMain.text) {
                const textDiv = document.createElement('div');
                const isLong = decMain.text.length > 320;
                textDiv.className = 'msg-text' + (isLong ? ' collapsed' : '');
                textDiv.textContent = decMain.text;
                bubble.appendChild(textDiv);

                if (isLong) {
                    const moreBtn = document.createElement('button');
                    moreBtn.type = 'button';
                    moreBtn.className = 'expand-btn';
                    moreBtn.dataset.action = 'toggle-expand';
                    moreBtn.textContent = 'نمایش کامل';
                    bubble.appendChild(moreBtn);
                }
            }

            row.appendChild(bubble);

            const footer = document.createElement('div');
            footer.className = 'msg-footer';

            const seenSpan = document.createElement('span');
            seenSpan.className = 'meta-pill';
            seenSpan.textContent = '👁️ ' + (msg.seen_count || 1);
            footer.appendChild(seenSpan);

            if (msg.reply_count > 0) {
                const repBadge = document.createElement('span');
                repBadge.className = 'meta-pill';
                repBadge.textContent = '💬 ' + msg.reply_count;
                footer.appendChild(repBadge);
            }

            const replyBtn = document.createElement('button');
            replyBtn.type = 'button';
            replyBtn.className = 'msg-act-btn';
            replyBtn.dataset.action = 'reply';
            replyBtn.textContent = '↩️ پاسخ';
            footer.appendChild(replyBtn);

            const copyBtn = document.createElement('button');
            copyBtn.type = 'button';
            copyBtn.className = 'msg-act-btn';
            copyBtn.dataset.action = 'copy';
            copyBtn.textContent = '📋 کپی';
            footer.appendChild(copyBtn);

            const pinBtn = document.createElement('button');
            pinBtn.type = 'button';
            pinBtn.className = 'msg-act-btn' + (msg.pinned ? ' pinned' : '');
            pinBtn.dataset.action = 'pin';
            pinBtn.textContent = msg.pinned ? '📌 سنجاق‌شده' : '📌 سنجاق';
            footer.appendChild(pinBtn);

            if (isOwn || CONFIG.isAdmin) {
                if (isOwn && decMain.status !== 'locked' && decMain.status !== 'mismatch') {
                    const editBtn = document.createElement('button');
                    editBtn.type = 'button';
                    editBtn.className = 'msg-act-btn';
                    editBtn.dataset.action = 'edit';
                    editBtn.textContent = '✏️ ویرایش';
                    footer.appendChild(editBtn);
                }
                const delBtn = document.createElement('button');
                delBtn.type = 'button';
                delBtn.className = 'msg-act-btn';
                delBtn.dataset.action = 'delete';
                delBtn.textContent = '🗑️';
                footer.appendChild(delBtn);
            }

            row.appendChild(footer);
            return row;
        }

        async function renderMessagesBatch(messages, clearExisting = false) {
            const wasBottom = isNearBottom();
            if (clearExisting) {
                State.messagesMap.clear();
                DOM.viewport.innerHTML = '';
            }

            if (messages.length > 0) {
                const emptyNode = DOM.viewport.querySelector('.empty-state');
                if (emptyNode) emptyNode.remove();

                const frag = document.createDocumentFragment();
                for (const m of messages) {
                    State.messagesMap.set(Number(m.msg_id), m);
                    if (Number(m.msg_id) > State.lastMessageId) {
                        State.lastMessageId = Number(m.msg_id);
                    }
                    const existingDom = document.getElementById('msg-' + m.msg_id);
                    const builtNode = await buildMessageNode(m);
                    if (existingDom) {
                        existingDom.replaceWith(builtNode);
                    } else {
                        frag.appendChild(builtNode);
                    }
                }
                DOM.viewport.appendChild(frag);

                if (clearExisting || wasBottom) {
                    scrollToBottom();
                } else {
                    State.unreadInViewport += messages.length;
                    DOM.unreadBtn.textContent = `⬇️ ${State.unreadInViewport} پیام جدید`;
                    DOM.unreadBtn.style.display = 'block';
                }
            } else if (State.messagesMap.size === 0) {
                DOM.viewport.innerHTML = '<div class="empty-state">هنوز پیامی در این تاپیک ثبت نشده است.</div>';
            }
        }

        async function redecryptViewportMessages() {
            const allMsgs = Array.from(State.messagesMap.values());
            if (allMsgs.length === 0) return;
            const frag = document.createDocumentFragment();
            for (const m of allMsgs) {
                frag.appendChild(await buildMessageNode(m));
            }
            DOM.viewport.innerHTML = '';
            DOM.viewport.appendChild(frag);
        }

        async function renderPinnedList(pinnedArray) {
            if (!Array.isArray(pinnedArray)) return;
            if (pinnedArray.length === 0) {
                DOM.pinnedBar.style.display = 'none';
                DOM.pinnedList.innerHTML = '';
                return;
            }
            DOM.pinnedBar.style.display = 'block';
            const frag = document.createDocumentFragment();
            for (const p of pinnedArray) {
                const dec = p.is_encrypted ? await CryptoEngine.decryptText(p.content) : { text: p.content };
                const row = document.createElement('div');
                row.className = 'pinned-row';
                row.dataset.action = 'jump';
                row.dataset.targetId = String(p.msg_id);

                const uSpan = document.createElement('span');
                uSpan.className = 'pinned-user';
                uSpan.textContent = p.username + ':';

                const sSpan = document.createElement('span');
                sSpan.className = 'pinned-snippet';
                sSpan.textContent = dec.text || (p.is_image ? '[تصویر]' : '[فایل]');

                row.appendChild(uSpan);
                row.appendChild(sSpan);
                frag.appendChild(row);
            }
            DOM.pinnedList.innerHTML = '';
            DOM.pinnedList.appendChild(frag);
        }
        function renderTopicsBar(topics, unreadMap) {
            const sig = JSON.stringify({ t: topics, u: unreadMap, c: State.currentTopicId });
            if (State._topicsSig === sig) return;
            State._topicsSig = sig;

            State.topics = topics;
            State.unreadCounts = unreadMap || {};

            let addWrap = DOM.topicsBar.querySelector('.topic-QuickAdd');
            if (CONFIG.isAdmin && !addWrap) {
                addWrap = document.createElement('div');
                addWrap.className = 'topic-QuickAdd';
                const inp = document.createElement('input');
                inp.type = 'text';
                inp.id = 'quickTopicInput';
                inp.placeholder = 'تاپیک جدید...';
                inp.maxLength = 40;
                inp.autocomplete = 'off';
                inp.addEventListener('keydown', e => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        addWrap.querySelector('button').click();
                    }
                });
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.dataset.topicAction = 'create';
                btn.textContent = '+';
                addWrap.appendChild(inp);
                addWrap.appendChild(btn);
                DOM.topicsBar.appendChild(addWrap);
            }

            DOM.topicsBar.querySelectorAll('.topic-pill').forEach(el => el.remove());

            const frag = document.createDocumentFragment();
            for (const t of topics) {
                const tid = Number(t.id);
                const pill = document.createElement('div');
                pill.className = 'topic-pill' + (tid === State.currentTopicId ? ' active' : '');
                pill.dataset.topicId = String(tid);

                const unread = Number(unreadMap[tid] || 0);
                if (unread > 0) {
                    const badge = document.createElement('span');
                    badge.className = 'unread-counter';
                    badge.textContent = String(unread);
                    pill.appendChild(badge);
                }

                const nameSpan = document.createElement('span');
                nameSpan.textContent = t.name;
                pill.appendChild(nameSpan);

                if (CONFIG.isAdmin) {
                    const clearBtn = document.createElement('button');
                    clearBtn.type = 'button';
                    clearBtn.className = 'topic-admin-act';
                    clearBtn.dataset.topicAction = 'purge';
                    clearBtn.dataset.topicId = String(tid);
                    clearBtn.title = 'پاک‌سازی پیام‌های این تاپیک';
                    clearBtn.textContent = '🗑️';
                    pill.appendChild(clearBtn);

                    if (topics.length > 1) {
                        const delBtn = document.createElement('button');
                        delBtn.type = 'button';
                        delBtn.className = 'topic-admin-act';
                        delBtn.dataset.topicAction = 'delete';
                        delBtn.dataset.topicId = String(tid);
                        delBtn.title = 'حذف کامل تاپیک';
                        delBtn.textContent = '✕';
                        pill.appendChild(delBtn);
                    }
                }
                frag.appendChild(pill);
            }

            if (addWrap) {
                DOM.topicsBar.insertBefore(frag, addWrap);
            } else {
                DOM.topicsBar.appendChild(frag);
            }
        }

        /* =========================================================================
         * 4. Unified Sync Loop
         * ========================================================================= */
        async function syncState(forceReset = false) {
            if (State.syncInFlight) return;
            State.syncInFlight = true;

            if (forceReset) {
                State.lastMessageId = 0;
                State.topicVersion = 0;
            }

            const typingParam = State.typingFlag;
            State.typingFlag = -1;

            try {
                const res = await apiCall('sync', {
                    topic_id: State.currentTopicId,
                    last_id: State.lastMessageId,
                    topic_version: State.topicVersion,
                    is_typing: typingParam
                });

                if (!res || !res.success) return;

                if (Number(res.topic_id) !== State.currentTopicId) {
                    State.currentTopicId = Number(res.topic_id);
                    State.lastMessageId = 0;
                }

                const shouldClear = Boolean(res.reload_topic) || forceReset;
                if (shouldClear) {
                    State.lastMessageId = 0;
                }

                State.topicVersion = Number(res.topic_version || 1);

                if (Array.isArray(res.messages) && (res.messages.length > 0 || shouldClear)) {
                    await renderMessagesBatch(res.messages, shouldClear);
                } else if (State.messagesMap.size === 0) {
                    await renderMessagesBatch([], true);
                }

                if (res.pinned !== null && res.pinned !== undefined) {
                    await renderPinnedList(res.pinned);
                }

                if (Array.isArray(res.topics)) {
                    renderTopicsBar(res.topics, res.unread_counts || {});
                }

                DOM.onlineBadge.textContent = String(res.online_count || 1);
                if (Array.isArray(res.online_users)) {
                    DOM.onlineStrip.innerHTML = '';
                    for (const u of res.online_users) {
                        const chip = document.createElement('span');
                        chip.className = 'online-chip';
                        const dot = document.createElement('span');
                        dot.className = 'online-dot';
                        const txt = document.createElement('span');
                        txt.textContent = u;
                        chip.appendChild(dot);
                        chip.appendChild(txt);
                        DOM.onlineStrip.appendChild(chip);
                    }
                }

                if (Array.isArray(res.typing) && res.typing.length > 0) {
                    DOM.typingBar.textContent = '✍️ ' + res.typing.join('، ') + ' در حال نوشتن...';
                } else {
                    DOM.typingBar.textContent = '';
                }

                if (res.chat_locked && !CONFIG.isAdmin) {
                    DOM.msgInput.disabled = true;
                    DOM.msgInput.placeholder = '🔒 چت‌روم موقتاً توسط مدیریت قفل شده است.';
                } else {
                    DOM.msgInput.disabled = false;
                    if (!State.replyTarget && !State.editTarget) {
                        DOM.msgInput.placeholder = 'پیام خود را بنویسید...';
                    }
                }

                DOM.imgLabel.style.display = (res.allow_uploads || CONFIG.isAdmin) ? 'flex' : 'none';
            } catch (err) {
                console.error('Sync error:', err);
            } finally {
                State.syncInFlight = false;
            }
        }

        function schedulePolling() {
            if (State.pollTimer) clearInterval(State.pollTimer);
            const interval = document.hidden ? CONFIG.hiddenPollIntervalMs : CONFIG.pollIntervalMs;
            State.pollTimer = setInterval(() => syncState(false), interval);
        }

        /* =========================================================================
         * 5. Actions & Event Handlers
         * ========================================================================= */
        function setComposerMode(mode, msgObj = null) {
            State.replyTarget = null;
            State.editTarget = null;
            if (!mode || !msgObj) {
                DOM.stateBar.classList.remove('active');
                DOM.msgInput.placeholder = 'پیام خود را بنویسید...';
                return;
            }
            if (mode === 'reply') {
                State.replyTarget = msgObj;
                DOM.stateText.textContent = '↩️ در حال پاسخ به ' + msgObj.username;
                DOM.stateBar.classList.add('active');
                DOM.msgInput.focus();
            } else if (mode === 'edit') {
                State.editTarget = msgObj;
                DOM.stateText.textContent = '✏️ ویرایش پیام #' + msgObj.msg_id;
                DOM.stateBar.classList.add('active');
                DOM.msgInput.value = msgObj._plainText || '';
                DOM.msgInput.focus();
            }
        }

        async function submitComposer() {
            const rawText = DOM.msgInput.value;
            const imgFile = DOM.imgInput.files[0] || null;
            const npvtFile = DOM.npvtInput ? (DOM.npvtInput.files[0] || null) : null;

            if (State.editTarget) {
                if (!rawText.trim()) return;
                const enc = await CryptoEngine.encryptText(rawText);
                const res = await apiCall('edit_message', {
                    msg_id: State.editTarget.msg_id,
                    topic_id: State.currentTopicId,
                    content: enc.payload,
                    is_encrypted: enc.encrypted ? 1 : 0
                });
                if (res.success) {
                    DOM.msgInput.value = '';
                    DOM.msgInput.style.height = 'auto';
                    setComposerMode(null);
                    await syncState(true);
                } else {
                    alert(res.message || 'خطا در ویرایش پیام');
                }
                return;
            }

            if (!rawText.trim() && !imgFile && !npvtFile) return;

            DOM.sendBtn.disabled = true;
            try {
                const enc = await CryptoEngine.encryptText(rawText);
                let action = 'send_message';
                let fileObj = null;

                if (npvtFile) {
                    action = 'upload_npvt';
                    fileObj = { field: 'npvt_file', file: npvtFile };
                } else if (imgFile) {
                    fileObj = { field: 'image', file: imgFile };
                }

                const res = await apiCall(action, {
                    topic_id: State.currentTopicId,
                    content: enc.payload,
                    is_encrypted: enc.encrypted ? 1 : 0,
                    reply_to: State.replyTarget ? State.replyTarget.msg_id : ''
                }, fileObj);

                if (res.success) {
                    DOM.msgInput.value = '';
                    DOM.msgInput.style.height = 'auto';
                    DOM.imgInput.value = '';
                    if (DOM.npvtInput) DOM.npvtInput.value = '';
                    setComposerMode(null);
                    await syncState(false);
                    scrollToBottom();
                } else {
                    alert(res.message || 'خطا در ارسال پیام');
                }
            } finally {
                DOM.sendBtn.disabled = false;
            }
        }

        DOM.viewport.addEventListener('click', async e => {
            const target = e.target.closest('[data-action]');
            if (!target) return;

            const action = target.dataset.action;
            if (action === 'preview-img') {
                DOM.imgTarget.src = target.dataset.src || '';
                DOM.imgModal.classList.add('open');
                return;
            }
            if (action === 'jump') {
                const dest = document.getElementById('msg-' + target.dataset.targetId);
                if (dest) dest.scrollIntoView({ behavior: 'smooth', block: 'center' });
                return;
            }
            if (action === 'toggle-expand') {
                const txtNode = target.previousElementSibling;
                if (txtNode) {
                    const collapsed = txtNode.classList.toggle('collapsed');
                    target.textContent = collapsed ? 'نمایش کامل' : 'بستن';
                }
                return;
            }

            const msgRow = target.closest('.msg-row');
            if (!msgRow) return;
            const msgId = Number(msgRow.dataset.msgId);
            const msgObj = State.messagesMap.get(msgId);
            if (!msgObj) return;

            if (action === 'reply') {
                setComposerMode('reply', msgObj);
            } else if (action === 'edit') {
                setComposerMode('edit', msgObj);
            } else if (action === 'copy') {
                await navigator.clipboard.writeText(msgObj._plainText || '');
                const orig = target.textContent;
                target.textContent = '✅ کپی شد';
                setTimeout(() => { target.textContent = orig; }, 1000);
            } else if (action === 'pin') {
                const res = await apiCall('pin_message', { msg_id: msgId, topic_id: State.currentTopicId });
                if (res.success) await syncState(true);
            } else if (action === 'delete') {
                if (!confirm('این پیام حذف شود؟')) return;
                const res = await apiCall('delete_message', { msg_id: msgId, topic_id: State.currentTopicId });
                if (res.success) await syncState(true);
            }
        });

        DOM.pinnedList.addEventListener('click', e => {
            const row = e.target.closest('[data-action="jump"]');
            if (row) {
                const dest = document.getElementById('msg-' + row.dataset.targetId);
                if (dest) dest.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        });

        DOM.pinnedHead.addEventListener('click', () => {
            DOM.pinnedList.classList.toggle('collapsed');
        });

        DOM.topicsBar.addEventListener('click', async e => {
            const actBtn = e.target.closest('[data-topic-action]');
            if (actBtn) {
                e.stopPropagation();
                const tAct = actBtn.dataset.topicAction;
                const tid = Number(actBtn.dataset.topicId || 0);

                if (tAct === 'create') {
                    const inp = document.getElementById('quickTopicInput');
                    const name = inp ? inp.value.trim() : '';
                    if (!name) return;
                    const res = await apiCall('create_topic', { name });
                    if (res.success) {
                        inp.value = '';
                        inp.blur();
                        State._topicsSig = '';
                        await syncState(false);
                    } else alert(res.message);
                } else if (tAct === 'purge') {
                    if (!confirm('تمام پیام‌های این تاپیک پاک شوند؟')) return;
                    const res = await apiCall('delete_topic_messages', { topic_id: tid });
                    if (res.success) await syncState(true);
                } else if (tAct === 'delete') {
                    if (!confirm('این تاپیک و تمام پیام‌هایش حذف شوند؟')) return;
                    const res = await apiCall('delete_topic', { topic_id: tid });
                    if (res.success) {
                        if (State.currentTopicId === tid) State.currentTopicId = 1;
                        await syncState(true);
                    } else alert(res.message);
                }
                return;
            }

            const pill = e.target.closest('.topic-pill');
            if (pill) {
                const newTid = Number(pill.dataset.topicId);
                if (newTid && newTid !== State.currentTopicId) {
                    State.currentTopicId = newTid;
                    setComposerMode(null);
                    await syncState(true);
                }
            }
        });

        /* =========================================================================
         * 6. E2EE Key Management & Hash Sync
         * ========================================================================= */
        async function syncHashKey() {
            const rawHash = decodeURIComponent(window.location.hash.slice(1)).trim();
            await CryptoEngine.setPassphrase(rawHash);
            if (CryptoEngine.isActive()) {
                DOM.e2eBtn.className = 'crypto-status-btn secured';
                DOM.e2eText.textContent = 'رمزنگاری E2EE فعال';
                DOM.e2eBtn.firstChild.textContent = '🔒 ';
            } else {
                DOM.e2eBtn.className = 'crypto-status-btn plain';
                DOM.e2eText.textContent = 'بدون رمزنگاری';
                DOM.e2eBtn.firstChild.textContent = '🔓 ';
            }
            DOM.e2eInput.value = rawHash;
            await redecryptViewportMessages();
        }

        window.addEventListener('hashchange', syncHashKey);

        DOM.e2eBtn.addEventListener('click', () => {
            DOM.e2eInput.value = CryptoEngine.getPassphrase();
            DOM.e2eModal.classList.add('open');
        });
        document.getElementById('e2eModalClose').addEventListener('click', () => DOM.e2eModal.classList.remove('open'));
        document.getElementById('e2eRandomBtn').addEventListener('click', () => {
            const arr = new Uint8Array(12);
            window.crypto.getRandomValues(arr);
            DOM.e2eInput.value = Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
        });
        document.getElementById('e2eApplyBtn').addEventListener('click', async () => {
            const val = DOM.e2eInput.value.trim();
            if (val) window.location.hash = encodeURIComponent(val);
            else history.replaceState(null, '', window.location.pathname + window.location.search);
            await syncHashKey();
            DOM.e2eModal.classList.remove('open');
        });
        document.getElementById('e2eCopyLinkBtn').addEventListener('click', async () => {
            const val = DOM.e2eInput.value.trim();
            if (val) window.location.hash = encodeURIComponent(val);
            await navigator.clipboard.writeText(window.location.href);
            alert('لینک دعوت حاوی کلید رمزنگاری کپی شد.');
        });

        /* =========================================================================
         * 7. News Drawer & Admin Dashboard
         * ========================================================================= */
        async function loadNews() {
            const res = await apiCall('get_news');
            if (!res.success) return;
            DOM.newsList.innerHTML = '';
            if (res.news.length === 0) {
                DOM.newsList.innerHTML = '<div class="empty-state">خبری ثبت نشده است.</div>';
                return;
            }
            const frag = document.createDocumentFragment();
            for (const item of res.news) {
                const card = document.createElement('div');
                card.className = 'news-card';

                const txt = document.createElement('div');
                txt.className = 'news-text';
                txt.textContent = item.content;
                card.appendChild(txt);

                const meta = document.createElement('div');
                meta.className = 'news-meta';

                const rGroup = document.createElement('div');
                rGroup.className = 'react-group';
                const icons = { like: '👍', fire: '🔥', dislike: '👎' };
                for (const [rKey, emoji] of Object.entries(icons)) {
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.className = 'react-pill' + (item.user_reaction === rKey ? ' active' : '');
                    btn.textContent = `${emoji} ${item.reactions[rKey] || 0}`;
                    btn.addEventListener('click', async () => {
                        await apiCall('add_reaction', { news_id: item.id, reaction: rKey });
                        loadNews();
                    });
                    rGroup.appendChild(btn);
                }
                meta.appendChild(rGroup);

                const timeSpan = document.createElement('span');
                timeSpan.textContent = formatRelativeTime(item.created_at);
                meta.appendChild(timeSpan);

                card.appendChild(meta);
                frag.appendChild(card);
            }
            DOM.newsList.appendChild(frag);
        }

        document.getElementById('newsOpenBtn').addEventListener('click', () => {
            DOM.newsDrawer.classList.add('open');
            loadNews();
        });
        document.getElementById('newsCloseBtn').addEventListener('click', () => DOM.newsDrawer.classList.remove('open'));
        document.getElementById('newsSubmitBtn').addEventListener('click', async () => {
            const val = DOM.newsInput.value.trim();
            if (!val) return;
            const res = await apiCall('add_news', { content: val });
            if (res.success) {
                DOM.newsInput.value = '';
                loadNews();
            } else alert(res.message);
        });
        const purgeNewsBtn = document.getElementById('newsPurgeBtn');
        if (purgeNewsBtn) {
            purgeNewsBtn.addEventListener('click', async () => {
                if (!confirm('همه اخبار پاک شوند؟')) return;
                await apiCall('delete_all_news');
                loadNews();
            });
        }

        <?php if ($isAdmin): ?>
        const adminModal = document.getElementById('adminModal');
        async function loadAdminDashboard() {
            const res = await apiCall('admin_get_dashboard');
            if (!res.success) return;

            const s = res.stats;
            const statsGrid = document.getElementById('adminStatsGrid');
            statsGrid.innerHTML = '';
            const metrics = [
                ['کل پیام‌ها', s.total_messages],
                ['کاربران', s.total_users],
                ['تاپیک‌ها', s.total_topics],
                ['حجم داده (KB)', s.db_size_kb],
                ['حجم آپلود (KB)', s.upload_size_kb]
            ];
            for (const [lbl, val] of metrics) {
                const box = document.createElement('div');
                box.className = 'stat-box';
                const vDiv = document.createElement('div');
                vDiv.className = 'stat-val';
                vDiv.textContent = String(val);
                const lDiv = document.createElement('div');
                lDiv.className = 'stat-lbl';
                lDiv.textContent = lbl;
                box.appendChild(vDiv);
                box.appendChild(lDiv);
                statsGrid.appendChild(box);
            }

            const c = res.config;
            document.getElementById('cfgAppName').value = c.app_name;
            document.getElementById('cfgAdminUser').value = c.admin_username;
            document.getElementById('cfgAdminPass').value = '';
            document.getElementById('cfgTtlHours').value = c.ttl_hours;
            document.getElementById('cfgMaxMsgs').value = c.max_messages;
            document.getElementById('cfgChatLocked').checked = Boolean(c.chat_locked);
            document.getElementById('cfgAllowUploads').checked = Boolean(c.allow_uploads);

            const tbody = document.getElementById('adminUsersTbody');
            tbody.innerHTML = '';
            for (const u of res.users) {
                const tr = document.createElement('tr');

                const tdName = document.createElement('td');
                tdName.textContent = u.username + (u.role === 'admin' ? ' (مدیر)' : '');

                const tdIp = document.createElement('td');
                tdIp.textContent = u.ip_address;

                const tdStat = document.createElement('td');
                tdStat.textContent = u.banned ? '🚫 مسدود' : (u.online ? '🟢 آنلاین' : '⚪ آفلاین');

                const tdAct = document.createElement('td');
                if (u.role !== 'admin') {
                    const bBtn = document.createElement('button');
                    bBtn.type = 'button';
                    bBtn.className = 'btn-sm ' + (u.banned ? 'btn-success' : 'btn-danger');
                    bBtn.textContent = u.banned ? 'رفع مسدودی' : 'مسدودسازی + IP';
                    bBtn.addEventListener('click', async () => {
                        await apiCall('admin_toggle_ban', { target_user_id: u.user_id });
                        loadAdminDashboard();
                    });
                    tdAct.appendChild(bBtn);
                }

                tr.appendChild(tdName);
                tr.appendChild(tdIp);
                tr.appendChild(tdStat);
                tr.appendChild(tdAct);
                tbody.appendChild(tr);
            }
        }

        document.getElementById('adminOpenBtn').addEventListener('click', () => {
            adminModal.classList.add('open');
            loadAdminDashboard();
        });
        document.getElementById('adminModalClose').addEventListener('click', () => adminModal.classList.remove('open'));
        document.getElementById('adminSaveConfigBtn').addEventListener('click', async () => {
            const res = await apiCall('admin_save_config', {
                app_name: document.getElementById('cfgAppName').value,
                admin_username: document.getElementById('cfgAdminUser').value,
                admin_password: document.getElementById('cfgAdminPass').value,
                ttl_hours: document.getElementById('cfgTtlHours').value,
                max_messages: document.getElementById('cfgMaxMsgs').value,
                chat_locked: document.getElementById('cfgChatLocked').checked ? 1 : 0,
                allow_uploads: document.getElementById('cfgAllowUploads').checked ? 1 : 0
            });
            alert(res.message || 'ذخیره شد');
            if (res.success) {
                loadAdminDashboard();
                syncState(true);
            }
        });
        document.getElementById('adminPurgeAllBtn').addEventListener('click', async () => {
            if (!confirm('هشدار: تمام پیام‌ها و فایل‌های تمام تاپیک‌ها برای همیشه منهدم می‌شوند. ادامه می‌دهید؟')) return;
            const res = await apiCall('admin_purge_all');
            alert(res.message);
            loadAdminDashboard();
            syncState(true);
        });
        <?php endif; ?>

        /* =========================================================================
         * 8. General UI Bindings & Bootstrap
         * ========================================================================= */
        DOM.onlineToggle.addEventListener('click', () => DOM.onlineStrip.classList.toggle('visible'));
        DOM.stateCancel.addEventListener('click', () => setComposerMode(null));
        DOM.sendBtn.addEventListener('click', submitComposer);
        DOM.unreadBtn.addEventListener('click', scrollToBottom);
        DOM.imgModal.addEventListener('click', () => DOM.imgModal.classList.remove('open'));

        DOM.msgInput.addEventListener('input', function () {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 120) + 'px';
            State.typingFlag = this.value.trim() !== '' ? 1 : 0;
            if (State.typingDecayTimer) clearTimeout(State.typingDecayTimer);
            State.typingDecayTimer = setTimeout(() => { State.typingFlag = 0; }, 3500);
        });

        DOM.msgInput.addEventListener('keydown', e => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                submitComposer();
            } else if (e.key === 'Escape') {
                setComposerMode(null);
            }
        });

        DOM.imgInput.addEventListener('change', () => {
            if (DOM.imgInput.files[0]) submitComposer();
        });
        if (DOM.npvtInput) {
            DOM.npvtInput.addEventListener('change', () => {
                if (DOM.npvtInput.files[0]) submitComposer();
            });
        }

        DOM.viewport.addEventListener('scroll', () => {
            if (isNearBottom()) {
                State.unreadInViewport = 0;
                DOM.unreadBtn.style.display = 'none';
            }
        });

        document.getElementById('themeSwitchBtn').addEventListener('click', () => {
            const isLight = document.body.classList.toggle('light-mode');
            localStorage.setItem('chapar_theme', isLight ? 'light' : 'dark');
        });
        if (localStorage.getItem('chapar_theme') === 'light') {
            document.body.classList.add('light-mode');
        }

        document.getElementById('logoutBtn').addEventListener('click', async () => {
            if (!confirm('از حساب کاربری خارج می‌شوید؟')) return;
            await apiCall('logout');
            window.location.reload();
        });

        document.addEventListener('visibilitychange', schedulePolling);

        (async function initChapar() {
            await syncHashKey();
            await syncState(true);
            schedulePolling();
            DOM.msgInput.focus();
        })();
    })();
    </script>
</body>
</html>
