<?php
/**
 * Portal MOTP helpers.
 *
 * MOTP-Init-Secret and MOTP-PIN are read from the configured radreply table.
 * The submitted passcode is the configured PIN followed by the 6-digit TOTP.
 */

if (strpos($_SERVER['PHP_SELF'] ?? '', '/library/user_motp.php') !== false) {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/../../operators/library/totp.php';

function dalo_portal_motp_table(PDO $pdo, array $config): string
{
    $name = $config['CONFIG_DB_TBL_RADREPLY'] ?? null;
    if (!is_string($name) || preg_match('/\A[A-Za-z_][A-Za-z0-9_]{0,63}\z/D', $name) !== 1) {
        throw new InvalidArgumentException('Invalid radreply table');
    }
    return ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') ? '`' . $name . '`' : '"' . $name . '"';
}

/** Return both MOTP attributes, or null when either attribute is absent/empty. */
function dalo_portal_motp_attributes(PDO $pdo, array $config, string $username): ?array
{
    $username = trim($username);
    if ($username === '') {
        return null;
    }

    $table = dalo_portal_motp_table($pdo, $config);
    $stmt = $pdo->prepare("SELECT attribute,value FROM $table "
                        . "WHERE username=? AND attribute IN ('MOTP-Init-Secret','MOTP-PIN')");
    $stmt->execute(array($username));

    $attrs = array();
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $attribute = isset($row['attribute']) ? (string) $row['attribute'] : '';
        $value = isset($row['value']) ? trim((string) $row['value']) : '';
        if ($attribute !== '' && $value !== '' && !array_key_exists($attribute, $attrs)) {
            $attrs[$attribute] = $value;
        }
    }

    if (!isset($attrs['MOTP-Init-Secret'], $attrs['MOTP-PIN'])) {
        return null;
    }

    $pin = $attrs['MOTP-PIN'];
    $secret = $attrs['MOTP-Init-Secret'];
    if (!preg_match('/\A[0-9]+\z/D', $pin) || strlen($pin) > 32) {
        return null;
    }
    if (!preg_match('/\A[A-Z2-7]{16,128}\z/D', strtoupper($secret))
        || strlen($secret) % 8 !== 0) {
        return null;
    }

    return array('pin' => $pin, 'secret' => strtoupper($secret));
}

/** Verify the PIN prefix and TOTP suffix. */
function dalo_portal_motp_verify(array $attributes, string $passcode): bool
{
    $passcode = trim($passcode);
    $pin = $attributes['pin'];

    if (strlen($passcode) <= strlen($pin)
        || !hash_equals(substr($passcode, 0, strlen($pin)), $pin)) {
        return false;
    }

    $otp = substr($passcode, strlen($pin));
    if (!preg_match('/\A[0-9]{6}\z/D', $otp)) {
        return false;
    }

    return dalo_totp_verify($attributes['secret'], $otp);
}
?>
