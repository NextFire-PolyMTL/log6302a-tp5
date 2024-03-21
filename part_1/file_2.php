<?php
$clean = 'data';
$tainted = $_GET['data'];

$tainted2 = 'data' . $tainted . $clean;
$clean2 = 'data' . $clean;

sink($clean2);
sink($tainted2);
