import express, { type Request, type Response } from 'express';
import path from 'path'
import { fileURLToPath } from 'url';
import { pool } from './db/index.js';
import oidc from 'express-openid-connect'
import crypto from 'crypto'
import qrcode from 'qrcode'
import jwtpkg from 'express-oauth2-jwt-bearer'
import type { NextFunction } from 'express';

const app = express();
const PORT = process.env.PORT || 8080;

const __filename__ = fileURLToPath(import.meta.url)
const __dirname__ = path.dirname(__filename__)

app.use(express.json());
app.set('view engine', 'ejs')
app.set('views', path.join(__dirname__, 'views'))
app.set('trust proxy', 1)

const { auth, requiresAuth } = oidc
const { auth: jwtAuth, requiredScopes } = jwtpkg;

const checkJwt = jwtAuth({
  issuerBaseURL: requireEnv('ISSUER_BASE_URL'),
  audience: requireEnv('API_AUDIENCE'),
});

function requireEnv(name: string): string {
  const value = process.env[name]
  if (!value) {
    throw new Error(`Nedostaje varijabla okoline: ${name}`)
  }
  return value
}

app.use(
  auth({
    authRequired: false,
    auth0Logout: true,
    baseURL: requireEnv('BASE_URL'),
    issuerBaseURL: requireEnv('ISSUER_BASE_URL'),
    clientID: requireEnv('CLIENT_ID'),
    clientSecret: requireEnv('CLIENT_SECRET'),
    secret: requireEnv('SESSION_SECRET'),
    authorizationParams: { response_type: 'code', scope: 'openid profile email' },
    routes: {
      login: '/login',
      postLogoutRedirect: '/app',
    },
  })
)

//* STVARANJE TABLICE
async function initDb() {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS passes (
      id UUID PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      document VARCHAR(255) NOT NULL,
      issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
    );
  `;
  try {
    await pool.query(createTableQuery);
    console.log('✅ Tablica "passes" je spremna u bazi podataka.');
  } catch (error) {
    console.error('❌ Greška prilikom stvaranja tablice:', error);
  }
}

//* PREUSMJERAVANJE NA LOGIN

app.get('/login', (req: Request, res: Response) => {
  res.oidc.login({
    returnTo: '/app'
  })
})

//* POČETNA STRANICA

app.get('/', (req: Request, res: Response) => {
    res.redirect('/app')
})

app.get('/app', async (req: Request, res: Response) => {
    try {
        const total_passes = await pool.query('SELECT count(*) FROM passes')
        const active_passes = await pool.query("SELECT count(*) FROM passes WHERE status = 'ACTIVE'")

        const totalPasses = parseInt(total_passes.rows[0].count, 10)
        const activePasses = parseInt(active_passes.rows[0].count, 10)

        const userIsAuthenticated = req.oidc.isAuthenticated();
        let passes = []

        if (userIsAuthenticated) {
            const passesResult = await pool.query('SELECT * FROM passes ORDER BY issued_at DESC');
            passes = passesResult.rows;
        }

        res.render('home_page', {
            totalPasses,
            activePasses,
            userIsAuthenticated,
            user: req.oidc.user ?? null,
            passes
        })

    } catch (error) {
        res.status(500).send('Greška na poslužitelju.')
    }
})

//* JAVNI PREGLED PROPUSNICA

app.get('/app/info/:id', async (req: Request, res: Response) => {
  try {
    const result = await pool.query('SELECT * FROM passes WHERE id = $1', [req.params.id]);

    if (result.rows.length === 0) {
      return res.sendStatus(404)
    }

    res.render('info_page', { pass: result.rows[0] });
  } catch (error: any) {
    //* ne valjani id
    if (error.code === '22P02') {
      return res.sendStatus(404)
    }
    console.error(error);
    res.sendStatus(500)
  }
});

//* PONIŠTAVANJE I BRISANJE PROPUSNICA

app.post('/app/passes/:id/cancel', requiresAuth(), async (req: Request, res: Response) => {
  try {
    await pool.query("UPDATE passes SET status = 'CANCELLED' WHERE id = $1", [req.params.id]);
    res.redirect('/app');
  } catch (error) {
    console.error(error);
    res.status(500).send('Greška na poslužitelju.');
  }
});

app.post('/app/passes/:id/delete', requiresAuth(), async (req: Request, res: Response) => {
  try {
    await pool.query('DELETE FROM passes WHERE id = $1', [req.params.id]);
    res.redirect('/app');
  } catch (error) {
    console.error(error);
    res.status(500).send('Greška na poslužitelju.');
  }
});

//* M2M: dohvat propusnice

app.get(
  '/app/passes/:id',
  checkJwt,
  requiredScopes('read:passes'),
  async (req: Request, res: Response) => {
    try {
      const result = await pool.query('SELECT * FROM passes WHERE id = $1', [req.params.id]);

      if (result.rows.length === 0) {
        return res.sendStatus(404);
      }

      const p = result.rows[0];
      res.json({
        id: p.id,
        name: p.name,
        document: p.document,
        issuedAt: new Date(p.issued_at).toISOString(),
        status: p.status,
      });
    } catch (error: any) {
      if (error.code === '22P02') {
        res.sendStatus(404);
      }
      console.error(error);
      res.sendStatus(500);
    }
  }
);

//* M2M: izdavanje propusnice
app.post(
  '/app/passes',
  checkJwt,
  requiredScopes('create:passes'),
  async (req: Request, res: Response) => {
    try {
      const { name, document } = req.body ?? {};

      if (
        typeof name !== 'string' || name.trim() === '' ||
        typeof document !== 'string' || document.trim() === ''
      ) {
        return res.status(400).json({ error: 'name i document su obavezni' });
      }

      const id = crypto.randomUUID();
      await pool.query(
        "INSERT INTO passes (id, name, document, issued_at, status) VALUES ($1, $2, $3, now(), 'ACTIVE')",
        [id, name.trim(), document.trim()]
      );

      const baseUrl = requireEnv('BASE_URL');
      const png = await qrcode.toBuffer(`${baseUrl}/app/info/${id}`, { type: 'png' });

      res
        .status(201)
        .set({
          'Content-Type': 'image/png',
          Location: `${baseUrl}/app/passes/${id}`,
        })
        .send(png);
    } catch (error) {
      console.error(error);
      res.sendStatus(500);
    }
  }
);
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) return next(err);
  const status = err.status ?? 500;
  if (err.headers) res.set(err.headers); // npr. WWW-Authenticate
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 ? 'Greška na poslužitelju.' : err.message });
});

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server sluša na http://localhost:${PORT}`);
  });
});