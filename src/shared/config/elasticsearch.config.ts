import { registerAs } from '@nestjs/config'

export default registerAs('elasticsearch', () => ({
  node: process.env.ELASTICSEARCH_NODE,
  apiKey: process.env.ELASTICSEARCH_API_KEY,
  index: {
    products: process.env.ELASTICSEARCH_INDEX_PRODUCTS
  },
  connection: {
    timeout: process.env.ELASTICSEARCH_CONNECTION_TIMEOUT,
    maxRetries: process.env.ELASTICSEARCH_MAX_RETRIES,
    requestTimeout: process.env.ELASTICSEARCH_REQUEST_TIMEOUT
  }
}))
