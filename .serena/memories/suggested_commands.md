# Lệnh được đề xuất cho development

## Development Commands
```bash
# Chạy development server
npm run dev

# Build project
npm run build

# Chạy production server
npm run start

# Debug mode
npm run debug
```

## Database Commands
```bash
# Generate Prisma client
npm run generate

# Run migrations
npm run migrate

# Production migrations
npm run migrate:prod

# Open Prisma Studio
npm run studio
```

## Code Quality Commands
```bash
# Lint và fix code
npm run lint

# Format code
npm run format

# Run tests
npm run test

# Debug tests
npm run test:debug
```

## Data Management Commands
```bash
# Seed all data
npm run seed

# Initialize basic data
npm run init-seed-data

# Create permissions
npm run create-permissions

# Create sample products
npm run create-products

# Clear products
npm run clear-products
```

## Package Management
```bash
# Update dependencies
npm run update:package

# Clean and reinstall
npm run clean:package
```

## System Commands (Darwin/macOS)
```bash
# Git operations
git status
git add .
git commit -m "feat: description"
git push

# File operations
ls -la
cd src/routes
find . -name "*.ts" -type f
grep -r "import" src/

# Process management
ps aux | grep node
kill -9 <pid>
```

## Useful Aliases (có thể thêm vào .zshrc)
```bash
# Development
alias dev="npm run dev"
alias build="npm run build"
alias test="npm run test"

# Database
alias db:studio="npm run studio"
alias db:migrate="npm run migrate"
alias db:generate="npm run generate"

# Code quality
alias lint="npm run lint"
alias format="npm run format"
```