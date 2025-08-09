module.exports = {
  apps: [
    {
      name: 'server-shopsifu',
      script: './dist/main.js',
      watch: false,
      instances: process.env.PM2_INSTANCES || 'max',
      exec_mode: 'cluster',
      wait_ready: true,
      shutdown_with_message: true,
      exp_backoff_restart_delay: 1500,
      max_memory_restart: process.env.PM2_MAX_MEM || '1500M',
      instance_var: 'INSTANCE_ID',
      env: {
        NODE_ENV: 'development',
        PORT: 3000,
        UV_THREADPOOL_SIZE: 16
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000,
        UV_THREADPOOL_SIZE: 64
      },
      // Docker specific settings
      kill_timeout: 5000,
      listen_timeout: 20000,
      // Logging
      merge_logs: true,
      out_file: '/dev/stdout',
      error_file: '/dev/stderr',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      // Auto restart
      autorestart: true,
      max_restarts: 10,
      min_uptime: '10s'
    }
  ],
}
