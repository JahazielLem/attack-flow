# Custom CA Certificates

Place any corporate proxy root CA certificates here as `.crt` files.

The API image copies this directory at build time and imports any `.crt` files into the trust store.

Example:

```bash
cp /path/to/corporate-root-ca.crt certs/
docker compose -f docker-compose.api.yml up -d --build
```

If you replace a certificate, rebuild the API image so the trust store is refreshed.
