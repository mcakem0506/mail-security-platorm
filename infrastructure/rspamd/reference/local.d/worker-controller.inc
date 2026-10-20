# Контроллер слушает только 127.0.0.1; пароль — из хранилища секретов (§31).
secure_ip = "127.0.0.1";
.include(try=false) "/run/secrets/rspamd/controller.inc"
