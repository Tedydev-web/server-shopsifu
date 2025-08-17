// ecosystem.config.js
module.exports = {
  apps: [
    {
      name: 'server-shopsifu',
      script: './dist/main.js',
      exec_mode: 'cluster',
      instances: process.env.WEB_CONCURRENCY || 'max',
      // readiness/shutdown
      // wait_ready: true,            // chỉ bật nếu có code send 'ready'
      shutdown_with_message: true,

      // ổn định
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

      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        UV_THREADPOOL_SIZE: process.env.UV_THREADPOOL_SIZE || 8
      }
    }
  ]
}
