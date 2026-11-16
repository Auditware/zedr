module.exports = {
  apps: [
    {
      name: 'zedr-backend',
      script: 'cargo',
      args: 'run',
      cwd: './backend',
      interpreter: 'none',
      autorestart: true,
      watch: false,
      env_file: '../secrets/.env.server.local',
      env: {
        RUST_BACKTRACE: '1',
        ZEDR_TLS_CERT_PATH: '../certs/cert.pem',
        ZEDR_TLS_KEY_PATH: '../certs/key.pem',
        ZEDR_BINARIES_DIR: 'binaries'
      }
    },
    {
      name: 'zedr-frontend',
      script: 'npm',
      args: 'run dev',
      cwd: './frontend',
      interpreter: 'none',
      autorestart: true,
      watch: false,
      env_file: '../secrets/.env.server.local'
    }
  ]
}
