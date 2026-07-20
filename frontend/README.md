# SecAi dashboard

```bash
npm ci
npm run dev
```

Vite serves the dashboard locally. Production uses the Nginx image in `frontend/Dockerfile`; its entrypoint writes `/config.js`.
