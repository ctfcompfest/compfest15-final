// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import { securityCheck } from '@/utils';
import type { NextApiRequest, NextApiResponse } from 'next'
import * as fs from "node:fs";

export default function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  securityCheck([req.body], ['code/'], ['..', 'flag.txt', 'script']);

  if (req.body.source === "" || req.body.source === undefined) {
    return res.status(400).json({ status: 'failed', message: 'source cannot be empty.' });
  }

  const markdownpdf = require("markdown-pdf")
  const contentStream = fs.createReadStream(req.body.source);
  res.writeHead(200, {
    'Content-Type': 'application/pdf'
  })
  contentStream
    .pipe(markdownpdf({remarkable: {preset: 'commonmark'}}))
    .pipe(res);
}
