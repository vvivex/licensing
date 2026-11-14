# Vulonz license server setup

## Publish the GitHub Pages dashboard

The static dashboard is in `docs/`. In the repository, open **Settings → Pages**, choose **Deploy from a branch**, select `main` and `/docs`, then save. GitHub Pages will show the site URL when publishing finishes (for this account, it should be `https://vvivex.github.io/licensing/`).

The `licensing` repository is public so GitHub Pages can publish it on the current plan. This makes both the static dashboard and server source visible to everyone. Never commit admin passwords, Render secrets, generated license keys, or database files. If you later want the server source private, move only the `docs/` frontend into a separate public Pages repository and keep the backend in a private repository.

## Deploy to Render

1. In Render, create a **Blueprint** from the public `vvivex/licensing` repository. The included `render.yaml` configures the Flask service, persistent disk, health check, and `DASHBOARD_ORIGIN=https://vvivex.github.io`.
2. Set `APP_SECRET_KEY`, `KEY_HASH_SECRET`, and `ADMIN_PASSWORD` as Render environment secrets before deploying. Generate the first two independently from at least 32 random bytes (for example, run `python -c "import secrets; print(secrets.token_urlsafe(48))"` twice). Set a unique admin password of at least 16 characters and store it in a password manager. Keep `KEY_HASH_SECRET` unchanged; rotating it invalidates all existing keys.
3. Keep the Render persistent disk mounted at `/var/data`. The SQLite database is stored there so licenses survive deploys and restarts. Persistent disks may require a paid Render instance. Do not remove the disk; deleting it deletes all key records.
4. After deployment, enter the Render service's HTTPS URL and admin password on the GitHub Pages dashboard. The dashboard uses short-lived, revocable bearer sessions and sends requests only to the configured HTTPS server. The server allows browser API calls only from the configured GitHub Pages origin.
5. Create keys from the dashboard, copy each key when shown, and distribute it securely. The server stores only keyed hashes, so a key cannot be retrieved after it is created.
6. To migrate the desktop client, set `VULONZ_LICENSE_SERVER_URL` to the service's HTTPS URL in the environment used to launch the app. For packaged clients, configure that value in the build environment (or set the `LICENSE_SERVER_URL` default in `main.py`) before building and distributing them.

Each key activates on one installation. The app creates a random installation ID and a separate random installation credential, protects both the credential and saved key with Windows DPAPI for the current Windows user, and sends the credential over HTTPS. The server stores only its SHA-256 hash, so copying just a key and installation ID is not enough to validate another installation. Use **Reset device** in the dashboard before moving a key to another installation, and close the old app first. If you already activated a key with an older server version, reset its device binding once before using this version.

The client checks the server at startup and every five minutes; a server outage or revoked key locks the app after the next check. Keep the Render service available for the app to remain authorized. The installation credential makes casual UUID copying harder, but it is not hardware attestation: a determined user controlling the client can extract local secrets or patch the Python app to bypass its checks.

Use strong Render secrets stored only in Render's environment settings, and never put admin credentials or key-hashing secrets in the desktop app or repository. Back up the persistent disk before any migration or database maintenance.
