<?php
$clean = 'data';
$tainted = $_GET['data'];

$clean2 = filter($tainted);

sink($clean2);
