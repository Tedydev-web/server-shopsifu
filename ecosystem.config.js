module.exports = {
  apps: [
    {
      name: 'server-shopsifu',
      script: './dist/main.js',
      watch: false,
      instances: process.env.PM2_INSTANCES || 11,
      exec_mode: 'cluster',
      wait_ready: false,
      max_memory_restart: process.env.PM2_MAX_MEM || '1G',
      node_args: process.env.NODE_ARGS || '--max-old-space-size=1024',
      instance_var: 'INSTANCE_ID',
      env: {
        NODE_ENV: 'development',
        PORT: 3000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      // Docker specific settings
      kill_timeout: 5000,
      listen_timeout: 10000,
      // Logging
      log_file: './logs/combined.log',
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      // Monitoring
      pmx: true,
      // Auto restart
      autorestart: true,
      max_restarts: 10,
      min_uptime: '10s'
    }
  ],

  deploy: {
    production: {
      user: 'SSH_USERNAME',
      host: 'SSH_HOSTMACHINE',
      ref: 'origin/master',
      repo: 'GIT_REPOSITORY',
      path: 'DESTINATION_PATH',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': ''
    }
  }
}
