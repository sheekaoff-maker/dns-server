import * as client from 'prom-client';

export const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry, prefix: 'guardtime_dns_' });

export const dnsQueriesTotal = new client.Counter({
  name: 'dns_queries_total',
  help: 'Total DNS queries handled',
  labelNames: ['result'] as const, // resolved | error
  registers: [registry],
});

export const dnsResolveDuration = new client.Histogram({
  name: 'dns_resolve_duration_seconds',
  help: 'End-to-end time to handle one DNS query: policy check + (block-response build OR upstream forward)',
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2],
  registers: [registry],
});
