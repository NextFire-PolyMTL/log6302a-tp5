<?php
session_start();

function validateDate($date, $format = 'Y-m-d') {
    $d = DateTime::createFromFormat($format, $date);
    return $d && $d->format($format) == $date;
}

$links = array(
    'index.php'         => 'Home',
    'departments.php'   => 'Departments',
    'about.php'         => 'About',
    'contact.php'       => 'Contact',
);

$host = "mysql";
$db_name = "health";
$db_username = "root";
$db_password = "sploitme";
$conn = new mysqli($host, $db_username, $db_password, $db_name);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

