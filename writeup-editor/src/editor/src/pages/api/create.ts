// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from 'next'
import * as fs from "node:fs";

type Data = {
  status: string,
  message: string,
}

export default function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>
) {
  if (req.body.code === undefined || req.body.target === "" || req.body.target === undefined) {
    return res.status(400).json({ status: 'failed', message: 'code or target cannot be empty.' });
  }

  const targetStream = fs.createWriteStream(req.body.target);
  targetStream.write(req.body.code);
  targetStream.end();
  return res.status(200).json({ status: 'success', message: 'success.' });
}
