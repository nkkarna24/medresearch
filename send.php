<?php
// ── Config ──────────────────────────────────────────────
$to      = 'nkkarna24@gmail.com';
$subject = '[medresearch.me] New Contact Form Inquiry';
// ────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit; }

// ── Honeypot spam check ──
if (!empty($_POST['honeypot']) || !empty($_POST['_gotcha'])) {
    http_response_code(200);
    echo '✓ Message sent!';
    exit; }

// ── Validate ──
$name    = trim($_POST['name'] ?? '');
$email   = trim($_POST['email'] ?? '');
$service = trim($_POST['service'] ?? '');
$message = trim($_POST['message'] ?? '');

if (!$name || !$email || !$service || !$message) {
    http_response_code(400);
    echo 'All fields are required.';
    exit; }

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo 'Invalid email address.';
    exit; }

// ── Sanitize ──
$name    = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$email   = filter_var($email, FILTER_SANITIZE_EMAIL);
$service = htmlspecialchars($service, ENT_QUOTES, 'UTF-8');
$message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

// ── Headers ──
$headers  = "From: $name <$email>\r\n";
$headers .= "Reply-To: $email\r\n";
$headers .= "X-Mailer: PHP/" . phpversion();
$headers .= "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

// ── Body ──
$body  = "Name:     $name\n";
$body .= "Email:    $email\n";
$body .= "Service:  $service\n";
$body .= "---\n$message\n";

// ── Send ──
if (mail($to, $subject, $body, $headers)) {
    echo '✓ Message sent!';
} else {
    http_response_code(500);
    echo 'Mail delivery failed. Please try again or email us directly.';
}
