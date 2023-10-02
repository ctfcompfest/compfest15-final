// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import { securityCheck } from '@/utils';
import type { NextApiRequest, NextApiResponse } from 'next'
import * as fs from "node:fs";

export default function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  var dataSource = req.body;
  if (req.method === "GET") dataSource = req.query;
  
  securityCheck([dataSource], [':"code/'], ['..', 'flag.txt']);
  if (dataSource.source === "" || dataSource.source === undefined) {
    return res.status(400).json({ status: 'failed', message: 'source cannot be empty.' });
  }

  const markdownpdf = require("markdown-pdf")
  const contentStream = fs.createReadStream(dataSource.source.toString());
  res.writeHead(200, {
    'Content-Type': 'application/pdf',
    'content-disposition': `attachment; filename="${dataSource.source}.pdf"`,
  });

  contentStream
    .pipe(markdownpdf({remarkable: {preset: 'commonmark'}}))
    .pipe(res);
}
