package api

// builtinTemplates are compose files to start a project from. Secrets live in
// the .env part, so a project's compose file can be shared without them.
var builtinTemplates = []DockerTemplate{
	{
		ID: "builtin:nginx", Name: "Nginx", Logo: "nginx", Category: "Web",
		Description: "A web server serving the html folder next to the compose file.",
		Compose: `services:
  web:
    image: nginx:stable-alpine
    restart: unless-stopped
    ports:
      - "${PORT:-8080}:80"
    volumes:
      - ./html:/usr/share/nginx/html:ro
`,
		Env: "PORT=8080\n",
	},
	{
		ID: "builtin:postgres", Name: "PostgreSQL", Logo: "postgresql", Category: "Databases",
		Description: "PostgreSQL with its data in a named volume, listening on localhost only.",
		Compose: `services:
  db:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    ports:
      - "127.0.0.1:${PORT:-5432}:5432"
    volumes:
      - data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER}"]
      interval: 10s
      retries: 5

volumes:
  data:
`,
		Env: "POSTGRES_USER=app\nPOSTGRES_PASSWORD=change-me\nPOSTGRES_DB=app\nPORT=5432\n",
	},
	{
		ID: "builtin:mysql", Name: "MySQL", Logo: "mysql", Category: "Databases",
		Description: "MySQL 8 with its data in a named volume, listening on localhost only.",
		Compose: `services:
  db:
    image: mysql:8.4
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: ${MYSQL_DATABASE}
      MYSQL_USER: ${MYSQL_USER}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
    ports:
      - "127.0.0.1:${PORT:-3306}:3306"
    volumes:
      - data:/var/lib/mysql

volumes:
  data:
`,
		Env: "MYSQL_ROOT_PASSWORD=change-me\nMYSQL_DATABASE=app\nMYSQL_USER=app\nMYSQL_PASSWORD=change-me-too\nPORT=3306\n",
	},
	{
		ID: "builtin:redis", Name: "Redis", Logo: "redis", Category: "Databases",
		Description: "Redis with a password and append-only persistence.",
		Compose: `services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes", "--requirepass", "${REDIS_PASSWORD}"]
    ports:
      - "127.0.0.1:${PORT:-6379}:6379"
    volumes:
      - data:/data

volumes:
  data:
`,
		Env: "REDIS_PASSWORD=change-me\nPORT=6379\n",
	},
	{
		ID: "builtin:wordpress", Name: "WordPress", Logo: "wordpress", Category: "Web",
		Description: "WordPress with its own MariaDB.",
		Compose: `services:
  wordpress:
    image: wordpress:6-apache
    restart: unless-stopped
    depends_on: [db]
    ports:
      - "${PORT:-8080}:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: ${DB_PASSWORD}
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - site:/var/www/html
  db:
    image: mariadb:11
    restart: unless-stopped
    environment:
      MARIADB_DATABASE: wordpress
      MARIADB_USER: wordpress
      MARIADB_PASSWORD: ${DB_PASSWORD}
      MARIADB_RANDOM_ROOT_PASSWORD: "1"
    volumes:
      - db:/var/lib/mysql

volumes:
  site:
  db:
`,
		Env: "DB_PASSWORD=change-me\nPORT=8080\n",
	},
	{
		ID: "builtin:grafana", Name: "Grafana", Logo: "grafana", Category: "Monitoring",
		Description: "Dashboards for Prometheus, Loki, databases and more.",
		Compose: `services:
  grafana:
    image: grafana/grafana-oss:latest
    restart: unless-stopped
    ports:
      - "${PORT:-3000}:3000"
    environment:
      GF_SECURITY_ADMIN_USER: ${ADMIN_USER}
      GF_SECURITY_ADMIN_PASSWORD: ${ADMIN_PASSWORD}
    volumes:
      - data:/var/lib/grafana

volumes:
  data:
`,
		Env: "ADMIN_USER=admin\nADMIN_PASSWORD=change-me\nPORT=3000\n",
	},
	{
		ID: "builtin:uptime-kuma", Name: "Uptime Kuma", Logo: "uptimekuma", Category: "Monitoring",
		Description: "A self-hosted status page and uptime monitor.",
		Compose: `services:
  kuma:
    image: louislam/uptime-kuma:1
    restart: unless-stopped
    ports:
      - "${PORT:-3001}:3001"
    volumes:
      - data:/app/data

volumes:
  data:
`,
		Env: "PORT=3001\n",
	},
	{
		ID: "builtin:minio", Name: "MinIO", Logo: "minio", Category: "Storage",
		Description: "S3-compatible object storage with its console.",
		Compose: `services:
  minio:
    image: minio/minio:latest
    restart: unless-stopped
    command: server /data --console-address ":9001"
    ports:
      - "${API_PORT:-9000}:9000"
      - "${CONSOLE_PORT:-9001}:9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    volumes:
      - data:/data

volumes:
  data:
`,
		Env: "MINIO_ROOT_USER=admin\nMINIO_ROOT_PASSWORD=change-me-please\nAPI_PORT=9000\nCONSOLE_PORT=9001\n",
	},
	{
		ID: "builtin:gitea", Name: "Gitea", Logo: "gitea", Category: "Development",
		Description: "A light Git service with its own SQLite database.",
		Compose: `services:
  gitea:
    image: gitea/gitea:1
    restart: unless-stopped
    environment:
      USER_UID: "1000"
      USER_GID: "1000"
    ports:
      - "${HTTP_PORT:-3000}:3000"
      - "${SSH_PORT:-2222}:22"
    volumes:
      - data:/data

volumes:
  data:
`,
		Env: "HTTP_PORT=3000\nSSH_PORT=2222\n",
	},
	{
		ID: "builtin:adminer", Name: "Adminer", Category: "Databases",
		Description: "A database web UI for MySQL, PostgreSQL, SQLite and more.",
		Compose: `services:
  adminer:
    image: adminer:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:${PORT:-8081}:8080"
`,
		Env: "PORT=8081\n",
	},
	{
		ID: "builtin:dozzle", Name: "Dozzle", Category: "Monitoring",
		Description: "Live logs of every container in the browser (read-only Docker socket).",
		Compose: `services:
  dozzle:
    image: amir20/dozzle:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:${PORT:-8888}:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
`,
		Env: "PORT=8888\n",
	},
	{
		ID: "builtin:n8n", Name: "n8n", Logo: "n8n", Category: "Automation",
		Description: "Workflow automation with its data in a named volume.",
		Compose: `services:
  n8n:
    image: n8nio/n8n:latest
    restart: unless-stopped
    ports:
      - "${PORT:-5678}:5678"
    environment:
      N8N_HOST: ${HOST}
      GENERIC_TIMEZONE: ${TZ}
    volumes:
      - data:/home/node/.n8n

volumes:
  data:
`,
		Env: "HOST=localhost\nTZ=UTC\nPORT=5678\n",
	},
}
