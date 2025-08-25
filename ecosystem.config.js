module.exports = {
  apps: [
    {
      name: 'server-shopsifu',
      script: './dist/main.js',
      watch: 'false',
      instances: 'max',
      exec_mode: 'cluster',
      max_memory_restart: '2G',
      node_args: '--max-old-space-size=2048 --max-semi-space-size=512',
      instance_var: 'INSTANCE_ID',
      env: {
        NODE_ENV: 'production',
        UV_THREADPOOL_SIZE: '64',
        NODE_OPTIONS: '--max-old-space-size=2048 --max-semi-space-size=512',
        METRICS_BASE_PORT: 9500,
        SERVICE: 'api',
        APP_VERSION: process.env.GIT_SHA || 'dev'
      }
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
