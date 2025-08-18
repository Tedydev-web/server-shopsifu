module.exports = {
  apps: [
    {
      name: 'server-shopsifu',
      script: './dist/main.js',
      watch: 'false',
      instances: 32, // Tối ưu cho 32 cores
      exec_mode: 'cluster',
      max_memory_restart: '2G',
      node_args: '--max-old-space-size=2048 --max-semi-space-size=512',
      env: {
        NODE_ENV: 'development',
        UV_THREADPOOL_SIZE: '64',
        NODE_OPTIONS: '--max-old-space-size=2048 --max-semi-space-size=512'
      },
      env_production: {
        NODE_ENV: 'production',
        UV_THREADPOOL_SIZE: '64',
        NODE_OPTIONS: '--max-old-space-size=2048 --max-semi-space-size=512'
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
