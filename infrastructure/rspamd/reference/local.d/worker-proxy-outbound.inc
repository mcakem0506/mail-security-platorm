# Сгенерировано MSP. Направление задаёт слушатель, к которому подключился Postfix.
milter = yes;
timeout = 30s;
upstream "local" { default = yes; self_scan = yes; settings_id = "msp_outbound"; }
count = 1;
max_retries = 1;
discard_on_reject = false;
quarantine_on_reject = false;
spam_header = "";
