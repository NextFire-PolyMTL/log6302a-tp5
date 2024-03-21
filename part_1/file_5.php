<?php
function Func1() {
    $line = '';
    $n = 0;
    
    $n  = read();
    while ($n > 0) {
    	$n = $n - 1;
    	$line  = read();
    	switch ($n) {
    	case 1:
    	    $line = filter($line);
    	    break;
    	case 2:
    	    $line = $line . '+-%' . '\n';
    	    break;
    	case 3:
    	    $line = 'abc' . '123';
    	    break;
    	default:
    	    print('WARNING: undefined case');
    	}
    	sink($line);
    }
}
