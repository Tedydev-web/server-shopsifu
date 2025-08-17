// ecosystem.config.js - Single PM2 app with multiple instances for load balancing
module.exports = {
  apps: [
    {
      name: 'server-shopsifu',
      script: './dist/main.js',
      exec_mode: 'cluster',
      instances: 8, // Total 8 workers for load balancing
      port: 3000, // Base port
      host: '0.0.0.0',

      // Stability settings
      shutdown_with_message: true,
      exp_backoff_restart_delay: 1500,
      max_memory_restart: process.env.WORKER_MEM || '1500M',
      kill_timeout: 10000,
      listen_timeout: 10000,
      merge_logs: true,
      out_file: '/dev/stdout',
      error_file: '/dev/stderr',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      autorestart: true,
      max_restarts: 10,
      min_uptime: '10s',
      instance_var: 'INSTANCE_ID',

      // Docker-specific configuration
      daemon: false,

      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        UV_THREADPOOL_SIZE: process.env.UV_THREADPOOL_SIZE || 8
      },

      // Process management
      watch: false,
      ignore_watch: ['node_modules', 'logs', '*.log']
    }
  ]
}
