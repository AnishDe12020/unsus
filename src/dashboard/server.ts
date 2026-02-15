import index from './index.html';
import { scan } from '../scanner.ts';
import { fetchPackage } from '../npm.ts';
import { analyzeWithAI } from '../analyzers/llm.ts';
import { saveScan, getHistory, getScan, clearHistory } from './db.ts';

Bun.serve({
  port: 3000,
  idleTimeout: 255,
  routes: {
    '/': index,

    '/api/scan': {
      POST: async (req) => {
        const body = await req.json();
        const pkg = body.package;
        if (!pkg || typeof pkg !== 'string') {
          return Response.json({ error: 'missing package name' }, { status: 400 });
        }

        // SSE stream for progress updates
        const encoder = new TextEncoder();
        const stream = new ReadableStream({
          async start(controller) {
            let closed = false;
            const send = (event: string, data: any) => {
              if (closed) return;
              try {
                controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
              } catch { closed = true; }
            };

            // Keepalive ping every 10s so browser doesn't drop connection
            const keepalive = setInterval(() => {
              if (closed) { clearInterval(keepalive); return; }
              try { controller.enqueue(encoder.encode(': keepalive\n\n')); }
              catch { closed = true; clearInterval(keepalive); }
            }, 60_000);

            const finish = () => {
              clearInterval(keepalive);
              if (!closed) { closed = true; controller.close(); }
            };

            send('stage', { stage: 'fetch', status: 'running', message: `Fetching ${pkg} from npm...` });

            let fetched;
            try {
              fetched = await fetchPackage(pkg);
            } catch (e: any) {
              send('stage', { stage: 'fetch', status: 'error', message: e.message });
              send('error', { error: `Failed to fetch: ${e.message}` });
              finish();
              return;
            }
            send('stage', { stage: 'fetch', status: 'done', message: 'Package downloaded' });

            try {
              // Static analysis
              send('stage', { stage: 'static', status: 'running', message: 'Running static analysis (AST, entropy, metadata, binaries)...' });
              const result = await scan(fetched.dir, { dynamic: false });
              send('stage', { stage: 'static', status: 'done', message: `${result.findings.length} findings, ${result.iocs.length} IOCs` });

              // npm audit (already ran inside scan, report it)
              const auditFindings = result.findings.filter(f => f.type === 'npm-audit');
              if (auditFindings.length) {
                send('log', { stage: 'static', message: `npm audit: ${auditFindings[0]?.message || auditFindings.length + ' findings'}` });
              }

              // Threat intel (already ran inside scan)
              const tiFindings = result.findings.filter(f => f.type === 'threat-intel');
              if (tiFindings.length) {
                send('log', { stage: 'static', message: `Threat intel: ${tiFindings.length} match(es)` });
              }

              // Dynamic analysis
              send('stage', { stage: 'dynamic', status: 'running', message: 'Running Docker sandbox...' });
              let dynamicResult;
              try {
                const dynScan = await scan(fetched.dir, { dynamic: true });
                dynamicResult = dynScan.dynamicAnalysis;
                // merge dynamic findings into result
                const dynFindings = dynScan.findings.filter(f =>
                  f.type === 'dynamic-network' || f.type === 'dynamic-resource' || f.type === 'dynamic-fs'
                );
                result.findings.push(...dynFindings);
                result.dynamicAnalysis = dynamicResult;
                // recalc
                result.riskScore = dynScan.riskScore;
                result.riskLevel = dynScan.riskLevel;
                result.summary = dynScan.summary;

                const netCount = dynamicResult?.networkAttempts?.length || 0;
                send('stage', { stage: 'dynamic', status: 'done', message: netCount ? `${netCount} outbound connection(s) detected` : 'No suspicious activity' });
                if (dynamicResult?.timedOut) {
                  send('log', { stage: 'dynamic', message: 'Install timed out' });
                }
              } catch (e: any) {
                send('stage', { stage: 'dynamic', status: 'done', message: `Skipped: ${e.message}` });
              }

              // AI analysis
              send('stage', { stage: 'ai', status: 'running', message: 'Running AI analysis...' });
              const ai = await analyzeWithAI(result, fetched.dir);
              if (ai.provider) {
                send('stage', { stage: 'ai', status: 'done', message: `${ai.provider}: ${ai.verdict.toUpperCase()}` });
              } else {
                send('stage', { stage: 'ai', status: 'done', message: ai.reason });
              }

              const id = saveScan(result);
              send('result', { id, ...result, aiAnalysis: ai });
              finish();
            } catch (e: any) {
              send('error', { error: `Scan failed: ${e.message}` });
              finish();
            } finally {
              fetched.cleanup();
            }
          },
        });

        return new Response(stream, {
          headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
          },
        });
      },
    },

    '/api/history': {
      GET: () => Response.json(getHistory()),
      DELETE: () => { clearHistory(); return Response.json({ ok: true }); },
    },

    '/api/scan/:id': {
      GET: (req) => {
        const id = parseInt(req.params.id);
        const result = getScan(id);
        if (!result) return Response.json({ error: 'not found' }, { status: 404 });
        return Response.json(result);
      },
    },
  },

  development: {
    hmr: true,
    console: true,
  },
});

console.log('Dashboard running on http://localhost:3000');
