# Secret files

These files are read by Docker at startup and mounted into containers at `/run/secrets/`.
They are never committed to Git (ТЗ 28) — the `.gitignore` in this directory enforces that.

Generate them before the first start:

```bash
umask 077
openssl rand -base64 48 | tr -d '\n' > msp_secret_key
openssl rand -base64 32 | tr -d '\n' > minio_password
```

If VirusTotal is licensed, add its key the same way and point `MSP_VT_API_KEY_FILE` at it:

```bash
printf '%s' 'your-key' > vt_api_key
```

Rotation: replace the file contents and restart the affected services. Rotating
`msp_secret_key` invalidates every session, which is the intended behaviour.
