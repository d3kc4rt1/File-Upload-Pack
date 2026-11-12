<?php header("Content-Type: text/plain"); $v=@file_get_contents('/tmp/pentest-canary.txt',false,null,0,4096); echo $v===false ? "pentest: canary unavailable" : $v; ?>
