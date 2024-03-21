<?php

$tainted = $_GET['data'];
if($condition)
    $tainted = filter($tainted);

sink($tainted);
