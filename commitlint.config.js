module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'docs', 'style', 'refactor', 'test', 'chore', 'perf', 'revert', 'ci', 'build', 'i18n']
    ],
    'scope-enum': [
      2,
      'always',
      ['api', 'backend', 'frontend', 'db', 'auth', 'ui', 'perf', 'security', 'config', 'tests', 'docs']
    ],
    'scope-empty': [2, 'never'],
    'subject-case': [2, 'always', ['sentence-case', 'lower-case']],
    'body-leading-blank': [1, 'always'],
    'footer-leading-blank': [1, 'always'],
    'header-max-length': [2, 'always', 100]
    // Optional: enforce references (nếu bạn liên kết commit với Jira/GitHub Issues)
    // 'references-empty': [2, 'never'],
  }
}
