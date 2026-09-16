# attack_flow_builder

This template should help get you started developing with Vue 3 in Vite.

## Recommended IDE Setup

[VSCode](https://code.visualstudio.com/) + [Volar](https://marketplace.visualstudio.com/items?itemName=Vue.volar) (and disable Vetur).

## Type Support for `.vue` Imports in TS

TypeScript cannot handle type information for `.vue` imports by default, so we replace the `tsc` CLI with `vue-tsc` for type checking. In editors, we need [Volar](https://marketplace.visualstudio.com/items?itemName=Vue.volar) to make the TypeScript language service aware of `.vue` types.

## Customize configuration

See [Vite Configuration Reference](https://vite.dev/config/).

## Project Setup

```sh
npm install
```

### Compile and Hot-Reload for Development

```sh
npm run dev
```

### Type-Check, Compile and Minify for Production

```sh
npm run build
```

### Run Unit Tests with [Vitest](https://vitest.dev/)

```sh
npm run test:unit
```

### Lint with [ESLint](https://eslint.org/)

```sh
npm run lint
```

## Docker (standalone UI)

Build and run the UI container:

```sh
docker build -f Dockerfile.ui \
  --build-arg AFB_BASE_URL=/ \
  --build-arg VITE_API_BASE_URL=http://localhost:8000/api/v1 \
  -t attack-flow-ui:local .

docker run --rm -p 8080:80 attack-flow-ui:local
```

`VITE_API_BASE_URL` sets the API base URL used by the UI deployment configuration.

- Separate API/UI deployment default: `VITE_API_BASE_URL=http://localhost:8000/api/v1`
- Bundled proxy default: `VITE_API_BASE_URL_PROXY=/api/v1` (used by `docker-compose.proxy.yml`)

Or run with UI-only Docker Compose:

```sh
cp .env.example .env
docker compose -f docker-compose.ui.yml up --build
```

Optional same-origin proxy example:

- `deploy/nginx/ui-api-proxy.conf` shows a minimal nginx setup to serve UI files and proxy `/api/` to a separately deployed API.
- Separate UI/API deployment is still the default and supported model.

For full self-hosting guidance (API/UI separate deployment, persistence, env setup, and CORS notes), see `docs/deployment-self-hosting.md`.
