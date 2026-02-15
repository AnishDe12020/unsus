import index from './index.html';
import { scan } from '../scanner.ts';
import { fetchPackage } from '../npm.ts';
import { analyzeWithAI } from '../analyzers/llm.ts';
import { saveScan, getHistory, getScan } from './db.ts';

Bun.serve({
  port: 3000,
  routes: {
    '/': index,

    '/api/scan': {
      POST: async (req) => {
        const body = await req.json();
        const pkg = body.package;
        if (!pkg || typeof pkg !== 'string') {
          return Response.json({ error: 'missing package name' }, { status: 400 });
        }

        let fetched;
        try {
          fetched = await fetchPackage(pkg);
        } catch (e: any) {
          return Response.json({ error: `Failed to fetch: ${e.message}` }, { status: 400 });
        }

        try {
          const result = await scan(fetched.dir, { dynamic: true });
          const ai = await analyzeWithAI(result, fetched.dir);
          const id = saveScan(result);
          return Response.json({ id, ...result, aiAnalysis: ai });
        } catch (e: any) {
          return Response.json({ error: `Scan failed: ${e.message}` }, { status: 500 });
        } finally {
          fetched.cleanup();
        }
      },
    },

    '/api/history': {
      GET: () => Response.json(getHistory()),
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
