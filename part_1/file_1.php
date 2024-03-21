<?php
$clean = 'data';
$tainted = $_GET['data'];

sink($clean);
sink($tainted);
