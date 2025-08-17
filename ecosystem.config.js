// ecosystem.config.js - Multi-port PM2 configuration for Nginx Load Balancer
module.exports = {
  apps: [
    {
      name: 'server-shopsifu-3000',
      script: './dist/main.js',
      exec_mode: 'cluster',
      instances: 2,
      port: 3000,
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
      instances: 2,
      exec_mode: 'cluster',
      watch: false,
      ignore_watch: ['node_modules', 'logs', '*.log'],

      // Error handling
      max_restarts: 10,
      min_uptime: '10s',
      restart_delay: 4000
    },
    {
      name: 'server-shopsifu-3003',
      script: './dist/main.js',
      exec_mode: 'cluster',
      instances: 3,
      port: 3003,
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
        PORT: 3003,
        UV_THREADPOOL_SIZE: process.env.UV_THREADPOOL_SIZE || 8
      },

      // Process management
      instances: 3,
      exec_mode: 'cluster',
      watch: false,
      ignore_watch: ['node_modules', 'logs', '*.log'],

      // Error handling
      max_restarts: 10,
      min_uptime: '10s',
      restart_delay: 4000
    },
    {
      name: 'server-shopsifu-3004',
      script: './dist/main.js',
      exec_mode: 'cluster',
      instances: 3,
      port: 3004,
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
        PORT: 3004,
        UV_THREADPOOL_SIZE: process.env.UV_THREADPOOL_SIZE || 8
      },

      // Process management
      instances: 3,
      exec_mode: 'cluster',
      watch: false,
      ignore_watch: ['node_modules', 'logs', '*.log'],

      // Error handling
      max_restarts: 10,
      min_uptime: '10s',
      restart_delay: 4000
    }
  ]
}
