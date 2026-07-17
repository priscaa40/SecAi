# SecAi dashboard

```bash
npm ci
npm run dev
```

Vite serves the dashboard locally. Production uses the Nginx image in `frontend/Dockerfile`; its entrypoint writes `/config.js` with only the public API base from `SECAI_API_BASE_URL`. Judge credentials remain in the API container and are never written into frontend runtime configuration.
