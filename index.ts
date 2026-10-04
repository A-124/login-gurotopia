import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import { SQL } from 'bun';

const app = express();

const MAX_ATTEMPTS = 5;
const COOLDOWN_MS = 30 * 60 * 1000;

const dbUrl = process.env.DATABASE_URL || 'mysql://root:password@localhost:3306/growtopia';
const db = new SQL(dbUrl);

const ipAttempts = new Map<string, { count: number; blockedUntil: number }>();

function getClientIp(req: Request): string {
  const xff = req.headers['x-forwarded-for'];
  const xri = req.headers['x-real-ip'];
  const forwarded = Array.isArray(xff) ? xff[0] : xff;
  const realIp = Array.isArray(xri) ? xri[0] : xri;
  return (
    (forwarded as string)?.split(',')[0]?.trim() ||
    (realIp as string) ||
    req.socket.remoteAddress ||
    'unknown'
  );
}

function checkIpBlocked(clientIp: string): { blocked: boolean; remaining: number } {
  const record = ipAttempts.get(clientIp);
  if (!record) return { blocked: false, remaining: MAX_ATTEMPTS };
  const now = Date.now();
  if (record.blockedUntil > now) return { blocked: true, remaining: 0 };
  if (record.blockedUntil > 0 && record.blockedUntil <= now) {
    ipAttempts.delete(clientIp);
    return { blocked: false, remaining: MAX_ATTEMPTS };
  }
  return { blocked: false, remaining: MAX_ATTEMPTS - record.count };
}

function recordFailedAttempt(clientIp: string): number {
  const record = ipAttempts.get(clientIp) || { count: 0, blockedUntil: 0 };
  const now = Date.now();
  if (record.blockedUntil > now) return 0;
  record.count += 1;
  const remaining = MAX_ATTEMPTS - record.count;
  if (record.count >= MAX_ATTEMPTS) {
    record.blockedUntil = now + COOLDOWN_MS;
  }
  ipAttempts.set(clientIp, record);
  return Math.max(0, remaining);
}

function resetAttempts(clientIp: string): void {
  ipAttempts.delete(clientIp);
}

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
});
app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

app.get('/', (_req: Request, res: Response) => {
  res.send('Hello, world!');
});

app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  const body = req.body;
  let clientData = '';
  if (body && typeof body === 'object' && Object.keys(body).length > 0) {
    clientData = Object.keys(body)[0];
  }
  const encodedClientData = Buffer.from(clientData).toString('base64');
  const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
  const templateContent = fs.readFileSync(templatePath, 'utf-8');
  const htmlContent = templateContent.replace('{{ data }}', encodedClientData);
  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  const clientIp = getClientIp(req);
  const { blocked } = checkIpBlocked(clientIp);
  if (blocked) {
    const errorMessage = 'Login attempts exhausted from your IP, Please try again later after 30 mins';
    const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
    const templateContent = fs.readFileSync(templatePath, 'utf-8');
    const errorHtml = `<div class="text-danger text-danger-wrapper"><ul><li>${errorMessage}</li></ul></div>`;
    let htmlContent = templateContent.replace('{{ data }}', Buffer.from('').toString('base64'));
    htmlContent = htmlContent.replace('<div class="row div-content-center">', `${errorHtml}<div class="row div-content-center">`);
    res.setHeader('Content-Type', 'text/html');
    res.send(htmlContent);
    return;
  }
  try {
    const formData = req.body as Record<string, string>;
    if (formData.email) return;
    const _token = formData._token;
    const growId = formData.growId;
    const password = formData.password;
    if (!growId || !password) {
      res.status(200).json({ status: 'error', message: 'Missing growId or password' });
      return;
    }
    const rows = await db`SELECT * FROM peer WHERE growid = ${growId} LIMIT 1`;
    if (rows.length === 0) {
      const attemptsLeft = recordFailedAttempt(clientIp);
      const clientData = Buffer.from(`${growId}`).toString('base64');
      const errorMessage = `Account credentials missmatched. You have ${attemptsLeft} attempt(s) left.`;
      const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
      const templateContent = fs.readFileSync(templatePath, 'utf-8');
      const errorHtml = `<div class="text-danger text-danger-wrapper"><ul><li>${errorMessage}</li></ul></div>`;
      let htmlContent = templateContent.replace('{{ data }}', clientData);
      htmlContent = htmlContent.replace('<div class="row div-content-center">', `${errorHtml}<div class="row div-content-center">`);
      res.setHeader('Content-Type', 'text/html');
      res.send(htmlContent);
      return;
    }
    const user = rows[0];
    if (user.password !== password) {
      const attemptsLeft = recordFailedAttempt(clientIp);
      const clientData = Buffer.from(`${growId}`).toString('base64');
      const errorMessage = `Account credentials missmatched. You have ${attemptsLeft} attempt(s) left.`;
      const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
      const templateContent = fs.readFileSync(templatePath, 'utf-8');
      const errorHtml = `<div class="text-danger text-danger-wrapper"><ul><li>${errorMessage}</li></ul></div>`;
      let htmlContent = templateContent.replace('{{ data }}', clientData);
      htmlContent = htmlContent.replace('<div class="row div-content-center">', `${errorHtml}<div class="row div-content-center">`);
      res.setHeader('Content-Type', 'text/html');
      res.send(htmlContent);
      return;
    }
    resetAttempts(clientIp);
    const token = Buffer.from(
      `_token=${_token}&growId=${growId}&password=${password}&reg=0`,
    ).toString('base64');
    res.send(JSON.stringify({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType: 'growtopia',
    }));
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Internal Server Error' });
  }
});

app.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
  try {
    let refreshToken: string | undefined;
    let clientData: string | undefined;
    const contentType = req.headers['content-type'] || '';
    if (typeof req.body === 'object' && req.body !== null) {
      const formData = req.body as Record<string, string>;
      if ('refreshToken' in formData || 'clientData' in formData) {
        refreshToken = formData.refreshToken;
        clientData = formData.clientData;
      } else if (Object.keys(formData).length === 1) {
        const rawPayload = Object.keys(formData)[0];
        const params = new URLSearchParams(rawPayload);
        refreshToken = params.get('refreshToken') || undefined;
        clientData = params.get('clientData') || undefined;
      }
    }
    if (!refreshToken || !clientData) {
      res.status(200).json({ status: 'error', message: 'Missing refreshToken or clientData' });
      return;
    }
    let decodedRefreshToken = Buffer.from(refreshToken, 'base64').toString('utf-8');
    if (decodedRefreshToken.includes('&reg=0')) {
      decodedRefreshToken = decodedRefreshToken.replace('&reg=0', '');
    } else if (decodedRefreshToken.includes('&reg=1')) {
      decodedRefreshToken = decodedRefreshToken.replace('&reg=1', '');
    }
    const token = Buffer.from(
      decodedRefreshToken.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString('base64')}`,
      ),
    ).toString('base64');
    res.send(JSON.stringify({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType: 'growtopia',
      accountAge: 2,
    }));
  } catch (error) {
    res.status(200).json({ status: 'error', message: 'Internal Server Error' });
  }
});

export default app;
